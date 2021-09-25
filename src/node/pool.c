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
#include <node/mempool.h>
#include <node/pool.h>
#include <node/timedata.h>

#include <satoshi/block.h>
#include <satoshi/bloom.h>
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

typedef struct btc_sendqueue_s {
  btc_invitem_t *head;
  btc_invitem_t *tail;
  size_t length;
} btc_sendqueue_t;

typedef struct btc_peer_s {
  struct btc_pool_s *pool;
  const btc_network_t *network;
  btc_logger_t *logger;
  btc_loop_t *loop;
  btc_socket_t *socket;
  parser_t parser;
  btc_sendqueue_t sending;
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
  btc_inv_t inv_queue;
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
  uint8_t last_tip[32];
  uint8_t last_stop[32];
  int64_t ping_timer;
  int64_t inv_timer;
  int64_t stall_timer;
  btc_filter_t addr_filter;
  btc_filter_t inv_filter;
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
  btc_invitem_t inv;
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
  khash_t(hashes) *block_map;
  khash_t(hashes) *tx_map;
  khash_t(hashes) *compact_map;
  int checkpoints_enabled;
  int bip37_enabled;
  int checkpoints;
  int listening;
  const btc_checkpoint_t *header_tip;
  btc_hdrentry_t *header_head;
  btc_hdrentry_t *header_tail;
  btc_hdrentry_t *header_next;
  int64_t refill_timer;
  unsigned int id;
  uint64_t required_services;
  size_t max_outbound;
  size_t max_inbound;
  int synced;
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

  parser_init(&peer->parser, peer->network->magic);
  parser_on_msg(&peer->parser, on_msg, peer);

  btc_inv_init(&peer->inv_queue);

  btc_filter_init(&peer->addr_filter);
  btc_filter_set(&peer->addr_filter, 5000, 0.001);

  btc_filter_init(&peer->inv_filter);
  btc_filter_set(&peer->inv_filter, 50000, 0.000001);

  peer->block_map = timemap_create();
  peer->tx_map = timemap_create();
  peer->compact_map = timemap_create();
  peer->response_map = typemap_create();

  return peer;
}

static void
btc_peer_clear_data(btc_peer_t *peer);

static void
btc_peer_destroy(btc_peer_t *peer) {
  khiter_t it;

  parser_clear(&peer->parser);

  btc_peer_clear_data(peer);

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

  btc_inv_clear(&peer->inv_queue);

  btc_filter_clear(&peer->addr_filter);
  btc_filter_clear(&peer->inv_filter);

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

static void
btc_pool_ban(struct btc_pool_s *pool, const btc_netaddr_t *addr);

static int
btc_peer_increase_ban(btc_peer_t *peer, int score) {
  peer->ban_score += score;

  if (peer->ban_score >= 100) {
    btc_peer_log(peer, "Ban threshold exceeded (%N).", &peer->addr);
    btc_pool_ban(peer->pool, &peer->addr);
    return 1;
  }

  return 0;
}

static int
btc_peer_write(btc_peer_t *peer, uint8_t *data, size_t length) {
  int rc = btc_socket_write(peer->socket, data, length);

  if (rc == -1) {
    const char *msg = btc_socket_strerror(peer->socket);

    btc_peer_log(peer, "Write error (%N): %s", &peer->addr, msg);
    btc_peer_close(peer);

    return 0;
  }

  return rc;
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

  return btc_peer_write(peer, data, length);
}

static int
btc_peer_sendmsg(btc_peer_t *peer, enum btc_msgtype type, const void *body) {
  btc_msg_t msg;

  btc_msg_set_type(&msg, type);

  msg.body = (void *)body;

  return btc_peer_send(peer, &msg);
}

static int
btc_peer_send_version(btc_peer_t *peer) {
  btc_version_t msg;

  btc_version_init(&msg);

  msg.version = BTC_NET_PROTOCOL_VERSION;
  msg.services = BTC_NET_LOCAL_SERVICES;
  msg.time = btc_timedata_now(peer->pool->timedata);
  msg.remote = peer->addr;

  btc_netaddr_init(&msg.local);

  msg.local.services = BTC_NET_LOCAL_SERVICES;
  msg.nonce = btc_nonces_alloc(&peer->pool->nonces, &peer->addr);

  strcpy(msg.agent, BTC_NET_USER_AGENT);

  msg.height = btc_chain_height(peer->pool->chain);
  msg.no_relay = 0;

  return btc_peer_sendmsg(peer, BTC_MSG_VERSION, &msg);
}

static int
btc_peer_send_verack(btc_peer_t *peer) {
  return btc_peer_sendmsg(peer, BTC_MSG_VERACK, NULL);
}

static int
btc_peer_send_ping(btc_peer_t *peer) {
  btc_ping_t ping;

  if (peer->state != BTC_PEER_CONNECTED)
    return 1;

  if (peer->version <= BTC_NET_PONG_VERSION) {
    ping.nonce = 0;
    return btc_peer_sendmsg(peer, BTC_MSG_PING, &ping);
  }

  if (peer->challenge != 0) {
    btc_peer_log(peer, "Peer has not responded to ping (%N).", &peer->addr);
    return 1;
  }

  peer->last_ping = btc_ms();
  peer->challenge = ((uint64_t)btc_random() << 32) | btc_random();

  ping.nonce = peer->challenge;

  return btc_peer_sendmsg(peer, BTC_MSG_PING, &ping);
}

static int
btc_peer_send_pong(btc_peer_t *peer, uint64_t nonce) {
  btc_pong_t pong = { nonce };

  return btc_peer_sendmsg(peer, BTC_MSG_PONG, &pong);
}

static int
btc_peer_send_getaddr(btc_peer_t *peer) {
  if (peer->sent_getaddr)
    return 1;

  peer->sent_getaddr = 1;

  return btc_peer_sendmsg(peer, BTC_MSG_GETADDR, NULL);
}

static int
btc_peer_send_addr(btc_peer_t *peer, const btc_addrs_t *addrs) {
  return btc_peer_sendmsg(peer, BTC_MSG_ADDR, addrs);
}

static int
btc_peer_send_addr_1(btc_peer_t *peer, const btc_netaddr_t *addr) {
  btc_netaddr_t *items[1];
  btc_addrs_t addrs = { items, 0, 1 };

  items[0] = (btc_netaddr_t *)addr;

  return btc_peer_send_addr(peer, &addrs);
}

static int
btc_peer_send_getblocks(btc_peer_t *peer,
                        const btc_vector_t *locator,
                        const uint8_t *stop) {
  const uint8_t *tip = NULL;
  btc_getblocks_t msg;

  msg.version = BTC_NET_PROTOCOL_VERSION;
  msg.locator = *locator;

  if (stop != NULL)
    btc_hash_copy(msg.stop, stop);
  else
    btc_hash_init(msg.stop);

  if (locator->length > 0)
    tip = (const uint8_t *)locator->items[0];

  btc_peer_log(peer, "Requesting inv message from peer with getblocks (%N).",
                     &peer->addr);

  btc_peer_log(peer, "Sending getblocks (tip=%H, stop=%H).", tip, stop);

  return btc_peer_sendmsg(peer, BTC_MSG_GETBLOCKS, &msg);
}

static int
btc_peer_send_getheaders(btc_peer_t *peer,
                         const btc_vector_t *locator,
                         const uint8_t *stop) {
  const uint8_t *tip = NULL;
  btc_getheaders_t msg;

  msg.version = BTC_NET_PROTOCOL_VERSION;
  msg.locator = *locator;

  if (stop != NULL)
    btc_hash_copy(msg.stop, stop);
  else
    btc_hash_init(msg.stop);

  if (locator->length > 0)
    tip = (const uint8_t *)locator->items[0];

  btc_peer_log(peer,
    "Requesting headers message from peer with getheaders (%N).",
    &peer->addr);

  btc_peer_log(peer, "Sending getheaders (tip=%H, stop=%H).", tip, stop);

  return btc_peer_sendmsg(peer, BTC_MSG_GETHEADERS, &msg);
}

static int
btc_peer_send_getheaders_1(btc_peer_t *peer,
                           const uint8_t *hash,
                           const uint8_t *stop) {
  void *items[1];
  btc_vector_t locator = { items, 0, 1 };

  items[0] = (void *)hash;

  return btc_peer_send_getheaders(peer, &locator, stop);
}

BTC_UNUSED static int
btc_peer_send_mempool(btc_peer_t *peer) {
  if (!(peer->services & BTC_NET_SERVICE_BLOOM)) {
    btc_peer_log(peer,
      "Cannot request mempool for non-bloom peer (%N).",
      &peer->addr);
    return 1;
  }

  btc_peer_log(peer,
    "Requesting inv message from peer with mempool (%N).",
    &peer->addr);

  return btc_peer_sendmsg(peer, BTC_MSG_MEMPOOL, NULL);
}

BTC_UNUSED static int
btc_peer_send_compact(btc_peer_t *peer, uint8_t mode) {
  btc_sendcmpct_t msg;

  msg.mode = mode;

  if (peer->services & BTC_NET_SERVICE_WITNESS) {
    if (peer->version >= BTC_NET_COMPACT_WITNESS_VERSION) {
      btc_peer_log(peer,
        "Initializing witness compact blocks (%N).",
        &peer->addr);

      msg.version = 2;

      return btc_peer_sendmsg(peer, BTC_MSG_SENDCMPCT, &msg);
    }
  }

  if (peer->version >= BTC_NET_COMPACT_VERSION) {
    btc_peer_log(peer,
      "Initializing normal compact blocks (%N).",
      &peer->addr);

    msg.version = 1;

    return btc_peer_sendmsg(peer, BTC_MSG_SENDCMPCT, &msg);
  }

  return 1;
}

static int
btc_peer_send_inv(btc_peer_t *peer, const btc_inv_t *msg) {
  size_t i;

  for (i = 0; i < msg->length; i++) {
    const btc_invitem_t *item = msg->items[i];

    btc_filter_add(&peer->inv_filter, item->hash, 32);
  }

  btc_peer_log(peer, "Serving %zu inv items to %N.",
                     msg->length, &peer->addr);

  return btc_peer_sendmsg(peer, BTC_MSG_INV, msg);
}

static int
btc_peer_send_getdata(btc_peer_t *peer, const btc_getdata_t *msg) {
  return btc_peer_sendmsg(peer, BTC_MSG_GETDATA, msg);
}

static int
btc_peer_send_notfound(btc_peer_t *peer, const btc_notfound_t *msg) {
  return btc_peer_sendmsg(peer, BTC_MSG_NOTFOUND, msg);
}

static int
btc_peer_send_headers(btc_peer_t *peer, const btc_headers_t *msg) {
  return btc_peer_sendmsg(peer, BTC_MSG_HEADERS, msg);
}

static int
btc_peer_send_reject(btc_peer_t *peer, const btc_reject_t *msg) {
  btc_peer_log(peer, "Rejecting %s %H (%N): code=%s reason=%s.",
                     msg->message,
                     msg->hash,
                     &peer->addr,
                     btc_reject_get_code(msg),
                     msg->reason);

  return btc_peer_sendmsg(peer, BTC_MSG_REJECT, msg);
}

static int
btc_peer_reject(btc_peer_t *peer,
                const char *message,
                const btc_verify_error_t *err) {
  btc_reject_t reject;

  btc_reject_init(&reject);

  strcpy(reject.message, message);
  btc_reject_set_code(&reject, err->code);
  strcpy(reject.reason, err->reason);
  btc_hash_copy(reject.hash, err->hash);

  btc_peer_send_reject(peer, &reject);

  return btc_peer_increase_ban(peer, err->score);
}

static int
btc_peer_flush_inv(btc_peer_t *peer) {
  int rc;

  if (peer->state != BTC_PEER_CONNECTED)
    return 1;

  if (peer->inv_queue.length == 0)
    return 1;

  btc_peer_log(peer, "Serving %zu inv items to %N.",
                     peer->inv_queue.length,
                     &peer->addr);

  rc = btc_peer_sendmsg(peer, BTC_MSG_INV, &peer->inv_queue);

  btc_inv_reset(&peer->inv_queue);

  return rc;
}

static int
btc_peer_announce(btc_peer_t *peer, uint32_t type, const uint8_t *hash) {
  if (btc_filter_has(&peer->inv_filter, hash, 32))
    return 0;

  btc_filter_add(&peer->inv_filter, hash, 32);
  btc_inv_push_item(&peer->inv_queue, type, hash);

  if (peer->inv_queue.length >= 500 || type == BTC_INV_BLOCK)
    btc_peer_flush_inv(peer);

  return 1;
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
    btc_peer_increase_ban(peer, 100);
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
    btc_peer_increase_ban(peer, 10);
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
  if (peer->state == BTC_PEER_DEAD) {
    btc_msg_destroy(msg);
    return;
  }

  switch (msg->type) {
    case BTC_MSG_VERSION:
      if (!btc_peer_on_version(peer, (const btc_version_t *)msg->body)) {
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
      btc_peer_on_ping(peer, (const btc_ping_t *)msg->body);
      break;
    case BTC_MSG_PONG:
      btc_peer_on_pong(peer, (const btc_pong_t *)msg->body);
      break;
    case BTC_MSG_SENDHEADERS:
      btc_peer_on_sendheaders(peer);
      break;
    case BTC_MSG_FEEFILTER:
      if (!btc_peer_on_feefilter(peer, (const btc_feefilter_t *)msg->body)) {
        btc_msg_destroy(msg);
        return;
      }
      break;
    case BTC_MSG_SENDCMPCT:
      btc_peer_on_sendcmpct(peer, (const btc_sendcmpct_t *)msg->body);
      break;
    default:
      break;
  }

  btc_pool_on_msg(peer->pool, peer, msg);
}

static int
btc_peer_flush_data(btc_peer_t *peer) {
  btc_chain_t *chain = peer->pool->chain;
  btc_mempool_t *mempool = peer->pool->mempool;
  btc_invitem_t *item, *next;
  btc_notfound_t nf;
  int blk_count = 0;
  int tx_count = 0;
  int64_t unknown = -1;
  size_t size;
  int ret = 1;

  if (peer->sending.length == 0)
    return 1;

  btc_inv_init(&nf);

  for (item = peer->sending.head; item != NULL; item = next) {
    next = item->next;
    size = btc_socket_buffered(peer->socket) + nf.length * 36;

    if (size >= (10 << 20)) {
      /* Wait for the peer to read
         before we pull more data
         out of the database. */
      ret = 0;
      break;
    }

    switch (item->type) {
      case BTC_INV_BLOCK: {
        const btc_entry_t *entry = btc_chain_by_hash(chain, item->hash);
        btc_block_t *block;

        if (entry == NULL) {
          btc_inv_push(&nf, item);
          break;
        }

        block = btc_chain_get_block(chain, entry);

        if (block == NULL) {
          btc_inv_push(&nf, item);
          break;
        }

        btc_peer_sendmsg(peer, BTC_MSG_BLOCK_BASE, block);

        btc_block_destroy(block);
        btc_invitem_destroy(item);

        blk_count += 1;

        break;
      }

      case BTC_INV_WITNESS_BLOCK: {
        const btc_entry_t *entry = btc_chain_by_hash(chain, item->hash);
        size_t length;
        uint8_t *data;

        if (entry == NULL) {
          btc_inv_push(&nf, item);
          break;
        }

        if (!btc_chain_get_raw_block(chain, &data, &length, entry)) {
          btc_inv_push(&nf, item);
          break;
        }

        btc_peer_write(peer, data, length);

        btc_invitem_destroy(item);

        blk_count += 1;

        break;
      }

      case BTC_INV_TX:
      case BTC_INV_WITNESS_TX: {
        const btc_mpentry_t *entry = btc_mempool_get(mempool, item->hash);

        if (entry == NULL) {
          btc_inv_push(&nf, item);
          break;
        }

        if (item->type == BTC_INV_TX)
          btc_peer_sendmsg(peer, BTC_MSG_TX_BASE, &entry->tx);
        else
          btc_peer_sendmsg(peer, BTC_MSG_TX, &entry->tx);

        btc_invitem_destroy(item);

        tx_count += 1;

        break;
      }

      default: {
        btc_inv_push(&nf, item);
        unknown = item->type;
        break;
      }
    }

    peer->sending.head = next;
    peer->sending.length--;

    if (next == NULL)
      peer->sending.tail = NULL;
  }

  if (nf.length > 0)
    btc_peer_send_notfound(peer, &nf);

  if (blk_count > 0) {
    btc_peer_log(peer,
      "Served %d blocks with getdata (notfound=%zu, cmpct=%d) (%N).",
      blk_count, nf.length, 0, &peer->addr);
  }

  if (tx_count > 0) {
    btc_peer_log(peer,
      "Served %d txs with getdata (notfound=%zu) (%N).",
      tx_count, nf.length, &peer->addr);
  }

  if (unknown != -1) {
    btc_peer_log(peer,
      "Peer sent an unknown getdata type: %u (%N).",
      (uint32_t)unknown, &peer->addr);
  }

  btc_inv_clear(&nf);

  return ret;
}

static void
btc_peer_send_data(btc_peer_t *peer, btc_invitem_t *item) {
  if (peer->sending.head == NULL)
    peer->sending.head = item;

  if (peer->sending.tail != NULL)
    peer->sending.tail->next = item;

  peer->sending.tail = item;
  peer->sending.length++;
}

static void
btc_peer_clear_data(btc_peer_t *peer) {
  btc_invitem_t *item, *next;

  for (item = peer->sending.head; item != NULL; item = next) {
    next = item->next;
    btc_invitem_destroy(item);
  }

  peer->sending.head = NULL;
  peer->sending.tail = NULL;
  peer->sending.length = 0;
}

static void
btc_peer_on_tick(btc_peer_t *peer) {
  int64_t now = btc_ms();

  if (now - peer->ping_timer >= 30000) {
    btc_peer_send_ping(peer);
    peer->ping_timer = now;
  }

  if (now - peer->inv_timer >= 5000) {
    btc_peer_flush_inv(peer);
    peer->inv_timer = now;
  }

  btc_peer_flush_data(peer);

  if (btc_socket_buffered(peer->socket) >= (30 << 20)) {
    btc_peer_close(peer);
    return;
  }

#if 0
  if (now - peer->stall_timer >= 5000)
    ; /* TODO: do stall checks */
#endif
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
 * Header Entry
 */

static btc_hdrentry_t *
btc_hdrentry_create(const uint8_t *hash, int32_t height) {
  btc_hdrentry_t *entry = (btc_hdrentry_t *)btc_malloc(sizeof(btc_hdrentry_t));

  btc_hash_copy(entry->inv.hash, hash);

  entry->inv.type = BTC_INV_BLOCK;
  entry->inv.next = NULL;
  entry->height = height;
  entry->next = NULL;

  return entry;
}

static void
btc_hdrentry_destroy(btc_hdrentry_t *entry) {
  btc_free(entry);
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
  pool->checkpoints_enabled = 1;
  pool->bip37_enabled = 0;
  pool->checkpoints = pool->checkpoints_enabled;
  pool->header_tip = NULL;
  pool->header_head = NULL;
  pool->header_tail = NULL;
  pool->header_next = NULL;
  pool->refill_timer = 0;
  pool->id = 0;
  pool->required_services = BTC_NET_LOCAL_SERVICES;
  pool->max_outbound = 8;
  pool->max_inbound = 8;
  pool->synced = 0;

  btc_loop_set_data(loop, 0, pool);
  btc_loop_on_tick(loop, on_tick);

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

static const btc_checkpoint_t *
btc_pool_next_tip(struct btc_pool_s *pool, int32_t height) {
  const btc_network_t *network = pool->network;
  const btc_checkpoint_t *chk;
  size_t i;

  for (i = 0; i < network->checkpoints.length; i++) {
    chk = &network->checkpoints.items[i];

    if (chk->height > height)
      return chk;
  }

  btc_abort(); /* LCOV_EXCL_LINE */
  return NULL; /* LCOV_EXCL_LINE */
}

static void
btc_pool_clear_chain(struct btc_pool_s *pool) {
  btc_hdrentry_t *entry, *next;

  for (entry = pool->header_head; entry != NULL; entry = next) {
    next = entry->next;
    btc_hdrentry_destroy(entry);
  }

  pool->checkpoints = 0;
  pool->header_tip = NULL;
  pool->header_head = NULL;
  pool->header_tail = NULL;
  pool->header_next = NULL;
}

static void
btc_pool_reset_chain(struct btc_pool_s *pool) {
  const btc_network_t *network = pool->network;
  const btc_entry_t *tip;

  if (!pool->checkpoints_enabled)
    return;

  if (network->checkpoints.length == 0)
    return;

  btc_pool_clear_chain(pool);

  tip = btc_chain_tip(pool->chain);

  if (tip->height < network->last_checkpoint) {
    pool->checkpoints = 1;
    pool->header_tip = btc_pool_next_tip(pool, tip->height);
    pool->header_head = btc_hdrentry_create(tip->hash, tip->height);
    pool->header_tail = pool->header_head;

    btc_pool_log(pool,
      "Initialized header chain to height %d (checkpoint=%H).",
      tip->height, pool->header_tip->hash);
  }
}

int
btc_pool_open(struct btc_pool_s *pool) {
  btc_pool_log(pool, "Opening pool.");

  if (!btc_addrman_open(pool->addrman))
    return 0;

  pool->synced = btc_chain_synced(pool->chain);

  btc_pool_reset_chain(pool);

  return 1;
}

void
btc_pool_close(struct btc_pool_s *pool) {
  btc_pool_clear_chain(pool);
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

    if (btc_addrman_has_local(pool->addrman, addr))
      continue;

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

static void
btc_pool_ban(struct btc_pool_s *pool, const btc_netaddr_t *addr) {
  btc_peer_t *peer = btc_peers_get(&pool->peers, addr);

  btc_pool_log(pool, "Banning peer (%N).", addr);

  btc_addrman_ban(pool->addrman, addr);

  if (peer != NULL)
    btc_peer_close(peer);
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

  if ((peer->services & pool->required_services) != pool->required_services)
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
  if (pool->network->request_mempool) {
    if (peer->loader && btc_chain_synced(pool->chain))
      btc_peer_send_mempool(peer);
  }

  peer->syncing = 1;
  peer->block_time = btc_ms();

  if (pool->checkpoints) {
    btc_peer_send_getheaders(peer, locator, pool->header_tip->hash);
    return 1;
  }

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
  const btc_netaddr_t *addr;

  /* Advertise our address. */
  if (peer->outbound) {
    if (pool->listening) {
      addr = btc_addrman_get_local(pool->addrman, &peer->addr);

      if (addr != NULL)
        btc_peer_send_addr_1(peer, addr);
    }

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
    if (!peer->loader && pool->peers.load != NULL) {
      if (pool->peers.load->state != BTC_PEER_CONNECTED) {
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
    if (pool->checkpoints)
      btc_pool_reset_chain(pool);
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
btc_pool_on_version(struct btc_pool_s *pool,
                    btc_peer_t *peer,
                    const btc_version_t *msg) {
  btc_pool_log(pool,
    "Received version (%N): version=%d height=%d services=%#.16llx agent=%s",
    &peer->addr,
    msg->version,
    msg->height,
    msg->services,
    msg->agent);

  if (pool->timedata != NULL) {
    size_t length = pool->timedata->length;
    int64_t offset = pool->timedata->offset;

    if (!btc_timedata_add(pool->timedata, msg->time)) {
      btc_pool_log(pool, "Adjusted time mismatch!");
      btc_pool_log(pool, "Please make sure your system clock is correct!");
    }

    if (pool->timedata->length != length) {
      int64_t sample = msg->time - btc_now();

      btc_pool_log(pool, "Added time data: total=%zu, sample=%T (%T minutes).",
                         pool->timedata->length, sample, sample / 60);
    }

    if (pool->timedata->offset != offset) {
      btc_pool_log(pool, "Time offset: %T (%T minutes).",
                         pool->timedata->offset,
                         pool->timedata->offset / 60);
    }
  }

  btc_nonces_remove(&pool->nonces, &peer->addr);

#if 0
  if (!peer->outbound && btc_netaddr_is_routable(&msg->remote))
    btc_addrman_mark_local(pool->addrman, &msg->remote);
#endif
}

static void
btc_pool_on_verack(struct btc_pool_s *pool, btc_peer_t *peer) {
  (void)pool;
  (void)peer;
}

static void
btc_pool_on_ping(struct btc_pool_s *pool,
                 btc_peer_t *peer,
                 const btc_ping_t *ping) {
  (void)pool;
  (void)peer;
  (void)ping;
}

static void
btc_pool_on_pong(struct btc_pool_s *pool,
                 btc_peer_t *peer,
                 const btc_pong_t *pong) {
  (void)pool;
  (void)peer;
  (void)pong;
}

static void
btc_pool_on_getaddr(struct btc_pool_s *pool, btc_peer_t *peer) {
  const btc_netaddr_t *addr;
  btc_addriter_t iter;
  btc_addrs_t addrs;
  int total = 0;

  if (peer->outbound) {
    btc_pool_log(pool, "Ignoring getaddr from outbound node (%N).",
                       &peer->addr);
    return;
  }

  if (peer->sent_addr) {
    btc_pool_log(pool, "Ignoring repeated getaddr (%N).",
                       &peer->addr);
    return;
  }

  peer->sent_addr = 1;

  btc_addrs_init(&addrs);

  btc_addrman_iterate(&iter, pool->addrman);

  while (btc_addrman_next(&addr, &iter)) {
    if (btc_filter_has_addr(&peer->addr_filter, addr))
      continue;

    total += 1;

    btc_filter_add_addr(&peer->addr_filter, addr);

    btc_addrs_push(&addrs, (btc_netaddr_t *)addr);

    if (addrs.length == 1000)
      break;
  }

  if (addrs.length > 0) {
    btc_peer_send_addr(peer, &addrs);
    addrs.length = 0;
  }

  btc_pool_log(pool, "Sent %d addrs to peer (%N)",
                     total, &peer->addr);

  btc_addrs_clear(&addrs);
}

static void
btc_pool_on_addr(struct btc_pool_s *pool,
                 btc_peer_t *peer,
                 btc_addrs_t *addrs) {
  uint64_t services = pool->required_services;
  int64_t now = btc_timedata_now(pool->timedata);
  int64_t since = now - 10 * 60;
  btc_vector_t relay;
  size_t i;

  if (addrs->length > 1000) {
    btc_peer_increase_ban(peer, 100);
    return;
  }

  btc_vector_init(&relay);

  for (i = 0; i < addrs->length; i++) {
    btc_netaddr_t *addr = addrs->items[i];

    btc_filter_add_addr(&peer->addr_filter, addr);

    if (!btc_netaddr_is_routable(addr))
      continue;

    if ((addr->services & services) != services)
      continue;

    if (addr->port == 0)
      continue;

    if (btc_addrman_is_banned(pool->addrman, addr))
      continue;

    if (addr->time <= 100000000 || addr->time > now + 10 * 60)
      addr->time = now - 5 * 24 * 60 * 60;

    if (!peer->getting_addr && addrs->length < 10) {
      if (addr->time > since)
        btc_vector_push(&relay, addr);
    }

    btc_addrman_add(pool->addrman, addr, &peer->addr);
  }

  if (addrs->length < 1000)
    peer->getting_addr = 0;

  btc_pool_log(pool,
    "Received %zu addrs (hosts=%zu, peers=%zu) (%N).",
    addrs->length,
    btc_addrman_size(pool->addrman),
    pool->peers.size,
    &peer->addr);

  if (relay.length > 0) {
    btc_vector_t peers;
    btc_peer_t *p;

    btc_pool_log(pool, "Relaying %zu addrs to random peers.", relay.length);

    btc_vector_init(&peers);

    for (p = pool->peers.head; p != NULL; p = p->next) {
      if (p->state == BTC_PEER_CONNECTED)
        btc_vector_push(&peers, p);
    }

    if (peers.length > 0) {
      for (i = 0; i < relay.length; i++) {
        btc_netaddr_t *addr = (btc_netaddr_t *)relay.items[i];
        uint32_t h1 = btc_murmur3_sum(addr->raw, 16, 0);
        uint32_t h2 = btc_murmur3_sum(addr->raw, 16, 1);
        btc_peer_t *peer1 = peers.items[h1 % peers.length];
        btc_peer_t *peer2 = peers.items[h2 % peers.length];

        if (!btc_filter_has_addr(&peer1->addr_filter, addr)) {
          btc_filter_add_addr(&peer1->addr_filter, addr);
          btc_peer_send_addr_1(peer1, addr);
        }

        if (!btc_filter_has_addr(&peer2->addr_filter, addr)) {
          btc_filter_add_addr(&peer2->addr_filter, addr);
          btc_peer_send_addr_1(peer2, addr);
        }
      }
    }

    btc_vector_clear(&peers);
  }

  btc_vector_clear(&relay);

  btc_pool_fill_outbound(pool);
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
btc_pool_get_block(struct btc_pool_s *pool,
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
                     btc_vector_t *inv) {
  btc_invitem_t *item;
  btc_vector_t out;
  size_t i;

  CHECK(inv->length > 0);

  /* Ignore for now if we're still syncing. */
  if (!btc_chain_synced(pool->chain) && !peer->loader)
    return;

  /* Request headers instead. */
  if (pool->checkpoints)
    return;

  btc_pool_log(pool, "Received %zu block hashes from peer (%N).",
                     inv->length, &peer->addr);

  btc_vector_init(&out);

  for (i = 0; i < inv->length; i++) {
    item = (btc_invitem_t *)inv->items[i];

    /* Ignore invalid (maybe ban?). */
    if (btc_chain_has_invalid(pool->chain, item->hash))
      continue;

    /* Resolve orphan chain. */
    if (btc_chain_has_orphan(pool->chain, item->hash)) {
      btc_pool_log(pool, "Received known orphan hash (%N).", &peer->addr);
      btc_pool_resolve_orphan(pool, peer, item->hash);
      continue;
    }

    /* Request the block if we don't have it. */
    if (!btc_chain_has_hash(pool->chain, item->hash)) {
      btc_vector_push(&out, item);
      continue;
    }

    /* Normally we request the hashContinue.
       In the odd case where we already have
       it, we can do one of two things: either
       force re-downloading of the block to
       continue the sync, or do a getblocks
       from the last hash. */
    if (i == inv->length - 1) {
      btc_pool_log(pool, "Received existing hash (%N).", &peer->addr);
      btc_pool_getblocks(pool, peer, item->hash, NULL);
    }
  }

  btc_pool_get_block(pool, peer, &out);

  btc_vector_clear(&out);
}

static void
btc_pool_get_tx(struct btc_pool_s *pool,
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

    if (hashset_has(pool->tx_map, item->hash))
      continue;

    hash = btc_hash_clone(item->hash);

    hashset_put(pool->tx_map, hash);
    timemap_put(peer->tx_map, hash, now);

    if (btc_chain_synced(pool->chain))
      now += 50;

    if (peer->services & BTC_NET_SERVICE_WITNESS)
      item->type |= BTC_INV_WITNESS_FLAG;

    btc_inv_push(&inv, item);
  }

  if (inv.length == 0) {
    btc_inv_clear(&inv);
    return;
  }

  if (timemap_size(peer->tx_map) >= BTC_NET_MAX_TX_REQUEST) {
    btc_pool_log(pool, "Peer advertised too many txs (%N).",
                       &peer->addr);
    btc_peer_close(peer);
    return;
  }

  btc_pool_log(pool, "Requesting %zu/%zu txs from peer with getdata (%N).",
                     inv.length, hashset_size(pool->tx_map), &peer->addr);

  btc_peer_send_getdata(peer, &inv);

  /* Caller must free up inv items. */
  inv.length = 0;

  btc_inv_clear(&inv);
}

static int
btc_pool_has_tx(struct btc_pool_s *pool, const uint8_t *hash) {
  /* Check the mempool. */
  if (btc_mempool_has(pool->mempool, hash))
    return 1;

  /* If we recently rejected this item. Ignore. */
  if (btc_mempool_has_reject(pool->mempool, hash)) {
    btc_pool_log(pool, "Saw known reject of %H.", hash);
    return 1;
  }

  return 0;
}

static void
btc_pool_on_txinv(struct btc_pool_s *pool,
                  btc_peer_t *peer,
                  btc_vector_t *inv) {
  /* Maybe move logic to pool_on_inv to avoid allocations. */
  btc_invitem_t *item;
  btc_vector_t out;
  size_t i;

  CHECK(inv->length > 0);

  if (!btc_chain_synced(pool->chain))
    return;

  btc_vector_init(&out);

  for (i = 0; i < inv->length; i++) {
    item = (btc_invitem_t *)inv->items[i];

    if (btc_pool_has_tx(pool, item->hash))
      continue;

    btc_vector_push(&out, item);
  }

  btc_pool_get_tx(pool, peer, &out);

  btc_vector_clear(&out);
}

static void
btc_pool_on_inv(struct btc_pool_s *pool, btc_peer_t *peer, btc_inv_t *inv) {
  int64_t unknown = -1;
  btc_invitem_t *item;
  btc_vector_t blocks;
  btc_vector_t txs;
  size_t i;

  if (inv->length > BTC_NET_MAX_INV) {
    btc_peer_increase_ban(peer, 100);
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

    btc_filter_add(&peer->inv_filter, item->hash, 32);
  }

  btc_pool_log(pool,
    "Received inv message with %zu items: blocks=%zu txs=%zu (%N).",
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
}

static void
btc_pool_on_getdata(struct btc_pool_s *pool,
                    btc_peer_t *peer,
                    btc_getdata_t *msg) {
  size_t i;

  if (msg->length > BTC_NET_MAX_INV) {
    btc_pool_log(pool, "Peer sent inv with >50k items (%n).",
                       &peer->addr);
    btc_peer_increase_ban(peer, 100);
    return;
  }

  for (i = 0; i < msg->length; i++)
    btc_peer_send_data(peer, msg->items[i]);

  btc_peer_flush_data(peer);

  /* Take ownership of the inv items. */
  msg->length = 0;
}

static void
btc_pool_on_notfound(struct btc_pool_s *pool,
                     btc_peer_t *peer,
                     const btc_notfound_t *msg) {
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
}

static void
btc_pool_on_getblocks(struct btc_pool_s *pool,
                      btc_peer_t *peer,
                      const btc_getblocks_t *msg) {
  const btc_entry_t *entry;
  btc_inv_t blocks;

  if (!btc_chain_synced(pool->chain))
    return;

#if 0
  if (btc_chain_pruned(pool->chain))
    return;
#endif

  entry = btc_chain_find_locator(pool->chain, &msg->locator);

  if (entry != NULL)
    entry = entry->next;

  btc_inv_init(&blocks);

  while (entry != NULL) {
    if (btc_hash_equal(entry->hash, msg->stop))
      break;

    /* Maybe store invitem on the entry? */
    btc_inv_push_item(&blocks, BTC_INV_BLOCK, entry->hash);

    if (blocks.length == 500) {
      btc_hash_copy(peer->hash_continue, entry->hash);
      break;
    }

    entry = entry->next;
  }

  btc_peer_send_inv(peer, &blocks);
  btc_inv_clear(&blocks);
}

static void
btc_pool_on_getheaders(struct btc_pool_s *pool,
                       btc_peer_t *peer,
                       const btc_getheaders_t *msg) {
  const btc_entry_t *entry;
  btc_headers_t blocks;

  if (!btc_chain_synced(pool->chain))
    return;

#if 0
  if (btc_chain_pruned(pool->chain))
    return;
#endif

  if (msg->locator.length > 0) {
    entry = btc_chain_find_locator(pool->chain, &msg->locator);

    if (entry != NULL)
      entry = entry->next;
  } else {
    entry = btc_chain_by_hash(pool->chain, msg->stop);
  }

  btc_headers_init(&blocks);

  while (entry != NULL) {
    btc_headers_push(&blocks, (btc_header_t *)&entry->header);

    if (btc_hash_equal(entry->hash, msg->stop))
      break;

    if (blocks.length == 2000)
      break;

    entry = entry->next;
  }

  btc_peer_send_headers(peer, &blocks);

  blocks.length = 0;

  btc_headers_clear(&blocks);
}

static void
btc_pool_resolve_headers(struct btc_pool_s *pool, btc_peer_t *peer) {
  btc_hdrentry_t *node;
  btc_vector_t items;

  btc_vector_init(&items);

  for (node = pool->header_next; node != NULL; node = node->next) {
    pool->header_next = node;

    btc_vector_push(&items, &node->inv);

    if (items.length == BTC_NET_MAX_INV)
      break;
  }

  btc_pool_get_block(pool, peer, &items);
  btc_vector_clear(&items);
}

static void
btc_pool_resolve_chain(struct btc_pool_s *pool,
                       btc_peer_t *peer,
                       const uint8_t *hash) {
  btc_hdrentry_t *node;

  if (!pool->checkpoints)
    return;

  if (!peer->loader)
    return;

  if (peer->state != BTC_PEER_CONNECTED)
    return;

  node = pool->header_head;

  CHECK(node != NULL);

  if (!btc_hash_equal(hash, node->inv.hash)) {
    btc_pool_log(pool, "Header hash mismatch %H != %H (%N).",
                       hash, node->inv.hash, &peer->addr);

    btc_peer_close(peer);

    return;
  }

  if (node->height < pool->network->last_checkpoint) {
    if (node->height == pool->header_tip->height) {
      btc_pool_log(pool, "Received checkpoint %H (%d).",
                         node->inv.hash, node->height);

      pool->header_tip = btc_pool_next_tip(pool, node->height);

      btc_peer_send_getheaders_1(peer, hash, pool->header_tip->hash);

      return;
    }

    /* Shift. */
    pool->header_head = node->next;

    btc_hdrentry_destroy(node);

    if (pool->header_head == NULL)
      pool->header_tail = NULL;

    btc_pool_resolve_headers(pool, peer);

    return;
  }

  btc_pool_log(pool, "Switching to getblocks (%N).",
                     &peer->addr);

  btc_pool_clear_chain(pool);

  btc_pool_getblocks(pool, peer, hash, NULL);
}

static void
btc_pool_on_headers(struct btc_pool_s *pool,
                    btc_peer_t *peer,
                    const btc_headers_t *msg) {
  btc_hdrentry_t *node = NULL;
  int checkpoint = 0;
  size_t i;

  if (!pool->checkpoints)
    return;

  if (!peer->loader)
    return;

  if (msg->length == 0)
    return;

  if (msg->length > 2000) {
    btc_peer_increase_ban(peer, 100);
    return;
  }

  CHECK(pool->header_head != NULL);

  for (i = 0; i < msg->length; i++) {
    const btc_header_t *hdr = msg->items[i];
    btc_hdrentry_t *last = pool->header_tail;
    int32_t height = last->height + 1;
    uint8_t hash[32];

    if (!btc_header_verify(hdr)) {
      btc_pool_log(pool, "Peer sent an invalid header (%N).",
                         &peer->addr);
      btc_peer_increase_ban(peer, 100);
      return;
    }

    if (!btc_hash_equal(hdr->prev_block, last->inv.hash)) {
      btc_pool_log(pool, "Peer sent a bad header chain (%N).",
                         &peer->addr);
      btc_peer_close(peer);
      return;
    }

    btc_header_hash(hash, hdr);

    if (height == pool->header_tip->height) {
      if (!btc_hash_equal(hash, pool->header_tip->hash)) {
        btc_pool_log(pool, "Peer sent an invalid checkpoint (%N).",
                           &peer->addr);
        btc_peer_close(peer);
        return;
      }
      checkpoint = 1;
    }

    node = btc_hdrentry_create(hash, height);

    if (pool->header_next == NULL)
      pool->header_next = node;

    if (pool->header_head == NULL)
      pool->header_head = node;

    if (pool->header_tail != NULL)
      pool->header_tail->next = node;

    pool->header_tail = node;
  }

  btc_pool_log(pool, "Received %zu headers from peer (%N).",
                     msg->length, &peer->addr);

  /* If we received a valid header
     chain, consider this a "block". */
  peer->block_time = btc_ms();

  /* Request the blocks we just added. */
  if (checkpoint) {
    /* Shift. */
    node = pool->header_head;
    pool->header_head = node->next;

    btc_hdrentry_destroy(node);

    if (pool->header_head == NULL)
      pool->header_tail = NULL;

    btc_pool_resolve_headers(pool, peer);

    return;
  }

  /* Request more headers. */
  btc_peer_send_getheaders_1(peer, node->inv.hash, pool->header_tip->hash);
}

static void
btc_pool_on_sendheaders(struct btc_pool_s *pool, btc_peer_t *peer) {
  (void)pool;
  (void)peer;
}

static void
btc_pool_announce(struct btc_pool_s *pool, uint32_t type, const uint8_t *hash) {
  btc_peer_t *peer;

  for (peer = pool->peers.head; peer != NULL; peer = peer->next) {
    if (peer->state != BTC_PEER_CONNECTED)
      continue;

    btc_peer_announce(peer, type, hash);
  }
}

static void
btc_pool_add_block(struct btc_pool_s *pool,
                   btc_peer_t *peer,
                   const btc_block_t *block,
                   unsigned int flags) {
  uint8_t hash[32];
  int32_t height;

  btc_header_hash(hash, &block->header);

  if (!btc_pool_resolve_block(pool, peer, hash)) {
    btc_pool_log(pool, "Received unrequested block: %H (%N).",
                       hash, &peer->addr);
    btc_peer_close(peer);
    return;
  }

  peer->block_time = btc_ms();

  if (!btc_chain_add(pool->chain, block, flags, peer->id)) {
    btc_peer_reject(peer, "block", btc_chain_error(pool->chain));
    return;
  }

  /* Block was orphaned. */
  if (btc_chain_has_orphan(pool->chain, hash)) {
    if (pool->checkpoints) {
      btc_pool_log(pool, "Peer sent orphan block with getheaders (%N).",
                         &peer->addr);
      return;
    }

    btc_pool_log(pool, "Peer sent an orphan block. Resolving.");
    btc_pool_resolve_orphan(pool, peer, hash);

    return;
  }

  if (!pool->synced && btc_chain_synced(pool->chain)) {
    pool->synced = 1;
    btc_pool_resync(pool, 0);
  }

  height = btc_chain_height(pool->chain);

  if (height % 20 == 0) {
    btc_pool_log(pool, "Status:"
                       " time=%D height=%d progress=%.2f%%"
                       " orphans=%d active=%zu"
                       " target=%#.8x peers=%zu",
      block->header.time,
      height,
      btc_chain_progress(pool->chain) * 100.0,
      0,
      hashset_size(pool->block_map),
      block->header.bits,
      pool->peers.size);
  }

  if (height % 2000 == 0) {
    btc_pool_log(pool, "Received 2000 more blocks (height=%d, hash=%H).",
                       height, hash);
  }

  btc_pool_resolve_chain(pool, peer, hash);

  if (btc_chain_synced(pool->chain))
    btc_pool_announce(pool, BTC_INV_BLOCK, hash);
}

static void
btc_pool_on_block(struct btc_pool_s *pool,
                  btc_peer_t *peer,
                  const btc_block_t *block) {
  btc_pool_add_block(pool, peer, block, BTC_CHAIN_DEFAULT_FLAGS);
}

static void
btc_pool_on_tx(struct btc_pool_s *pool, btc_peer_t *peer, const btc_tx_t *tx) {
  btc_vector_t missing;
  uint8_t hash[32];

  btc_tx_txid(hash, tx);

  if (!btc_pool_resolve_tx(pool, peer, hash)) {
    btc_pool_log(pool, "Peer sent unrequested tx: %x (%s).",
                       hash, &peer->addr);
    btc_peer_close(peer);
    return;
  }

  btc_vector_init(&missing);

  if (!btc_mempool_add(pool->mempool, &missing, tx, peer->id)) {
    btc_peer_reject(peer, "tx", btc_mempool_error(pool->mempool));
    btc_vector_clear(&missing);
    return;
  }

  if (missing.length > 0) {
    btc_pool_log(pool, "Requesting %zu missing transactions (%N).",
                       missing.length, &peer->addr);

    /* Must be an invitem vector. */
    btc_pool_get_tx(pool, peer, &missing);
    btc_vector_clear(&missing);

    return;
  }

  btc_vector_clear(&missing);

  btc_pool_announce(pool, BTC_INV_TX, hash);
}

static void
btc_pool_on_reject(struct btc_pool_s *pool,
                   btc_peer_t *peer,
                   const btc_reject_t *msg) {
  btc_pool_log(pool, "Received reject (%N): msg=%s code=%s reason=%s hash=%H.",
                     &peer->addr,
                     msg->message,
                     btc_reject_get_code(msg),
                     msg->reason,
                     msg->hash);
}

static void
btc_pool_on_mempool(struct btc_pool_s *pool, btc_peer_t *peer) {
  const btc_mpentry_t *entry;
  btc_mpiter_t iter;
  btc_inv_t items;

  if (!btc_chain_synced(pool->chain))
    return;

  if (!pool->bip37_enabled) {
    btc_pool_log(pool, "Peer requested mempool without bip37 enabled (%N).",
                       &peer->addr);
    btc_peer_close(peer);
    return;
  }

  btc_pool_log(pool, "Sending mempool snapshot (%N).", &peer->addr);

  btc_inv_init(&items);

  btc_mempool_iterate(&iter, pool->mempool);

  /* Maybe store invitem on the entry? */
  while (btc_mempool_next(&entry, &iter)) {
    btc_inv_push_item(&items, BTC_INV_TX, entry->hash);

    if (items.length == 1000) {
      btc_peer_send_inv(peer, &items);
      btc_inv_reset(&items);
    }
  }

  if (items.length > 0)
    btc_peer_send_inv(peer, &items);

  btc_inv_clear(&items);
}

static void
btc_pool_on_feefilter(struct btc_pool_s *pool,
                      btc_peer_t *peer,
                      const btc_feefilter_t *msg) {
  (void)pool;
  (void)peer;
  (void)msg;
}

static void
btc_pool_on_sendcmpct(struct btc_pool_s *pool,
                      btc_peer_t *peer,
                      const btc_sendcmpct_t *msg) {
  (void)pool;
  (void)peer;
  (void)msg;
}

static void
btc_pool_on_unknown(struct btc_pool_s *pool,
                    btc_peer_t *peer,
                    const btc_msg_t *msg) {
  btc_pool_log(pool, "Unknown message: %s (%N).", msg->cmd, &peer->addr);
}

static void
btc_pool_on_msg(struct btc_pool_s *pool, btc_peer_t *peer, btc_msg_t *msg) {
  switch (msg->type) {
    case BTC_MSG_VERSION:
      btc_pool_on_version(pool, peer, (const btc_version_t *)msg->body);
      break;
    case BTC_MSG_VERACK:
      btc_pool_on_verack(pool, peer);
      break;
    case BTC_MSG_PING:
      btc_pool_on_ping(pool, peer, (const btc_ping_t *)msg->body);
      break;
    case BTC_MSG_PONG:
      btc_pool_on_pong(pool, peer, (const btc_pong_t *)msg->body);
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
      btc_pool_on_notfound(pool, peer, (const btc_notfound_t *)msg->body);
      break;
    case BTC_MSG_GETBLOCKS:
      btc_pool_on_getblocks(pool, peer, (const btc_getblocks_t *)msg->body);
      break;
    case BTC_MSG_GETHEADERS:
      btc_pool_on_getheaders(pool, peer, (const btc_getheaders_t *)msg->body);
      break;
    case BTC_MSG_HEADERS:
      btc_pool_on_headers(pool, peer, (const btc_headers_t *)msg->body);
      break;
    case BTC_MSG_SENDHEADERS:
      btc_pool_on_sendheaders(pool, peer);
      break;
    case BTC_MSG_BLOCK:
      btc_pool_on_block(pool, peer, (const btc_block_t *)msg->body);
      break;
    case BTC_MSG_TX:
      btc_pool_on_tx(pool, peer, (const btc_tx_t *)msg->body);
      break;
    case BTC_MSG_REJECT:
      btc_pool_on_reject(pool, peer, (const btc_reject_t *)msg->body);
      break;
    case BTC_MSG_MEMPOOL:
      btc_pool_on_mempool(pool, peer);
      break;
    case BTC_MSG_FEEFILTER:
      btc_pool_on_feefilter(pool, peer, (const btc_feefilter_t *)msg->body);
      break;
    case BTC_MSG_SENDCMPCT:
      btc_pool_on_sendcmpct(pool, peer, (const btc_sendcmpct_t *)msg->body);
      break;
    case BTC_MSG_UNKNOWN:
      btc_pool_on_unknown(pool, peer, msg);
      break;
    default:
      break;
  }

  btc_msg_destroy(msg);
}
