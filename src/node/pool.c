/*!
 * pool.c - p2p pool for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <io/core.h>
#include <io/loop.h>

#include <base/addrman.h>
#include <node/chain.h>
#include <base/logger.h>
#include <node/mempool.h>
#include <node/pool.h>
#include <base/timedata.h>

#include <mako/bip37.h>
#include <mako/bip152.h>
#include <mako/block.h>
#include <mako/bloom.h>
#include <mako/coins.h>
#include <mako/consensus.h>
#include <mako/crypto/hash.h>
#include <mako/crypto/rand.h>
#include <mako/entry.h>
#include <mako/header.h>
#include <mako/list.h>
#include <mako/map.h>
#include <mako/net.h>
#include <mako/netaddr.h>
#include <mako/netmsg.h>
#include <mako/network.h>
#include <mako/policy.h>
#include <mako/script.h>
#include <mako/tx.h>
#include <mako/util.h>
#include <mako/vector.h>

#include "../bio.h"
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

typedef void btc_parser_on_msg_cb(btc_msg_t *msg, void *arg);
typedef void btc_parser_on_error_cb(void *arg);

typedef struct btc_parser_s {
  uint32_t magic;
  uint8_t *pending;
  size_t alloc;
  size_t total;
  size_t waiting;
  int closed;
  /* Header */
  char cmd[12];
  int has_header;
  uint32_t checksum;
  /* Callback */
  btc_parser_on_msg_cb *on_msg;
  btc_parser_on_error_cb *on_error;
  void *arg;
} btc_parser_t;

typedef struct btc_sendqueue_s {
  btc_invitem_t *head;
  btc_invitem_t *tail;
  size_t length;
} btc_sendqueue_t;

typedef struct btc_peer_s {
  btc_pool_t *pool;
  const btc_network_t *network;
  btc_logger_t *logger;
  btc_loop_t *loop;
  btc_socket_t *socket;
  btc_parser_t parser;
  btc_sendqueue_t sending;
  enum btc_peer_state state;
  unsigned int id;
  int outbound;
  int loader;
  btc_netaddr_t addr;
  btc_netaddr_t local;
  uint64_t nonce;
  int64_t time;
  int64_t last_send;
  int64_t last_recv;
  int ban_score;
  btc_inv_t inv_queue;
  uint32_t version;
  uint64_t services;
  int32_t height;
  char agent[256 + 1];
  int relay;
  int prefer_headers;
  uint8_t last_start[32];
  uint8_t last_stop[32];
  uint8_t hash_continue[32];
  int64_t fee_rate;
  int compact_mode;
  int compact_witness;
  int syncing;
  int sent_addr;
  int getting_addr;
  int sent_getaddr;
  uint64_t challenge;
  int64_t last_pong;
  int64_t last_ping;
  int64_t min_ping;
  int64_t block_time;
  int64_t gb_time;
  int64_t gh_time;
  int64_t ping_timer;
  int64_t inv_timer;
  int64_t stall_timer;
  btc_filter_t addr_filter;
  btc_filter_t inv_filter;
  btc_bloom_t *spv_filter;
  btc_hashtab_t block_map;
  btc_hashtab_t tx_map;
  btc_hashmap_t compact_map;
  struct btc_peer_s *prev;
  struct btc_peer_s *next;
} btc_peer_t;

typedef struct btc_nonces_s {
  btc_longset_t set;
} btc_nonces_t;

typedef struct btc_peers_s {
  btc_netmap_t map;
  btc_intmap_t ids;
  btc_peer_t *head;
  btc_peer_t *tail;
  btc_peer_t *load;
  size_t inbound;
  size_t outbound;
  size_t length;
} btc_peers_t;

typedef struct btc_hdrnode_s {
  uint8_t hash[32];
  int32_t height;
  struct btc_hdrnode_s *next;
} btc_hdrnode_t;

struct btc_pool_s {
  const btc_network_t *network;
  btc_loop_t *loop;
  btc_logger_t *logger;
  btc_timedata_t *timedata;
  btc_addrman_t *addrman;
  btc_chain_t *chain;
  btc_mempool_t *mempool;
  unsigned int flags;
  uint64_t services;
  int port;
  btc_vector_t bind;
  btc_vector_t connect;
  btc_sockaddr_t proxy;
  size_t max_inbound;
  size_t max_outbound;
  enum btc_ipnet only_net;
  btc_server_t *server;
  btc_peers_t peers;
  btc_nonces_t nonces;
  btc_hashset_t block_map;
  btc_hashset_t tx_map;
  btc_hashset_t compact_map;
  int block_mode;
  int checkpoints;
  const btc_checkpoint_t *header_tip;
  btc_hdrnode_t *header_head;
  btc_hdrnode_t *header_tail;
  btc_hdrnode_t *header_next;
  int64_t refill_timer;
  int64_t flush_timer;
  unsigned int id;
  uint64_t required_services;
  int synced;
};

BTC_DEFINE_LOGGER(btc_pool, btc_pool_t, "pool")
BTC_DEFINE_LOGGER(btc_peer, btc_peer_t, "peer")

/*
 * Nonce List
 */

static void
btc_nonces_init(btc_nonces_t *list) {
  btc_longset_init(&list->set);
}

static void
btc_nonces_clear(btc_nonces_t *list) {
  btc_longset_clear(&list->set);
}

static int
btc_nonces_has(btc_nonces_t *list, uint64_t nonce) {
  return btc_longset_has(&list->set, nonce);
}

static uint64_t
btc_nonces_alloc(btc_nonces_t *list) {
  for (;;) {
    uint64_t nonce = btc_nonce();

    if (UNLIKELY(nonce == 0))
      continue;

    if (!btc_longset_put(&list->set, nonce))
      continue;

    return nonce;
  }
}

static int
btc_nonces_remove(btc_nonces_t *list, uint64_t nonce) {
  return btc_longset_del(&list->set, nonce) != 0;
}

/*
 * Parser
 */

static void
btc_parser_init(btc_parser_t *parser, uint32_t magic) {
  parser->magic = magic;
  parser->pending = NULL;
  parser->alloc = 0;
  parser->total = 0;
  parser->waiting = 24;
  parser->closed = 0;
  parser->cmd[0] = '\0';
  parser->has_header = 0;
  parser->checksum = 0;
  parser->on_msg = NULL;
  parser->on_error = NULL;
  parser->arg = NULL;
}

static void
btc_parser_clear(btc_parser_t *parser) {
  if (parser->alloc > 0)
    btc_free(parser->pending);

  parser->pending = NULL;
}

static uint8_t *
btc_parser_append(btc_parser_t *parser, const uint8_t *data, size_t length) {
  if (parser->closed)
    return parser->pending;

  if (parser->total + length > parser->alloc) {
    parser->pending = btc_realloc(parser->pending, parser->total + length);
    parser->alloc = parser->total + length;
  }

  if (length > 0)
    memcpy(parser->pending + parser->total, data, length);

  parser->total += length;

  return parser->pending;
}

static int
btc_parser_parse_header(btc_parser_t *parser, const uint8_t **xp, size_t *xn) {
  uint32_t magic, size;

  if (!btc_uint32_read(&magic, xp, xn))
    return 0;

  if (magic != parser->magic)
    return 0;

  if (!btc_nullstr_read(parser->cmd, sizeof(parser->cmd), xp, xn))
    return 0;

  if (!btc_uint32_read(&size, xp, xn))
    return 0;

  if (size > BTC_NET_MAX_MESSAGE)
    return 0;

  if (!btc_uint32_read(&parser->checksum, xp, xn))
    return 0;

  parser->waiting = size;
  parser->has_header = 1;

  return 1;
}

static int
btc_parser_parse(btc_parser_t *parser, const uint8_t *data, size_t length) {
  btc_msg_t msg;

  CHECK(length <= BTC_NET_MAX_MESSAGE);

  if (!parser->has_header)
    return btc_parser_parse_header(parser, &data, &length);

  parser->waiting = 24;
  parser->has_header = 0;

  if (btc_checksum(data, length) != parser->checksum)
    return 0;

  btc_msg_set_cmd(&msg, parser->cmd);
  btc_msg_alloc(&msg);

  if (!btc_msg_import(&msg, data, length)) {
    btc_msg_clear(&msg);
    return 0;
  }

  parser->on_msg(&msg, parser->arg);

  btc_msg_clear(&msg);

  return 1;
}

static int
btc_parser_feed(btc_parser_t *parser, const uint8_t *data, size_t length) {
  uint8_t *ptr = btc_parser_append(parser, data, length);
  size_t len = parser->total;
  int parsed = 0;

  while (!parser->closed && len >= parser->waiting) {
    size_t size = parser->waiting;

    if (parser->has_header)
      parsed = 1;

    if (!btc_parser_parse(parser, ptr, size)) {
      if (!parser->closed)
        parser->on_error(parser->arg);
    }

    ptr += size;
    len -= size;
  }

  if (len > 0 && ptr != parser->pending)
    memmove(parser->pending, ptr, len);

  parser->total = len;

  return parsed;
}

/*
 * Events
 */

static void
btc_pool_on_tick(btc_pool_t *pool, int64_t now);

static void
btc_pool_on_socket(btc_pool_t *pool, btc_socket_t *socket);

static void
btc_peer_on_tick(btc_peer_t *peer, int64_t now);

static void
btc_peer_on_connect(btc_peer_t *peer);

static void
btc_peer_on_close(btc_peer_t *peer);

static void
btc_peer_on_error(btc_peer_t *peer, const char *msg);

static int
btc_peer_on_data(btc_peer_t *peer, const uint8_t *data, size_t size);

static void
btc_peer_on_drain(btc_peer_t *peer);

static void
btc_peer_on_msg(btc_peer_t *peer, btc_msg_t *msg);

static void
btc_peer_on_parse_error(btc_peer_t *peer);

static void
on_server_socket(btc_socket_t *listener, btc_socket_t *socket) {
  btc_socket_set_nodelay(socket, 1);
  btc_pool_on_socket((btc_pool_t *)btc_socket_get_data(listener), socket);
}

static void
on_tick(void *arg) {
  int64_t now = btc_time_msec();
  btc_pool_t *pool = (btc_pool_t *)arg;
  btc_peer_t *peer;

  for (peer = pool->peers.head; peer != NULL; peer = peer->next)
    btc_peer_on_tick(peer, now);

  btc_pool_on_tick(pool, now);
}

static void
on_connect(btc_socket_t *socket) {
  btc_socket_set_nodelay(socket, 1);
  btc_peer_on_connect((btc_peer_t *)btc_socket_get_data(socket));
}

static void
on_close(btc_socket_t *socket) {
  btc_peer_on_close((btc_peer_t *)btc_socket_get_data(socket));
}

static void
on_error(btc_socket_t *socket) {
  btc_peer_on_error((btc_peer_t *)btc_socket_get_data(socket),
                    btc_socket_strerror(socket));
}

static int
on_data(btc_socket_t *socket, const void *data, size_t size) {
  return btc_peer_on_data((btc_peer_t *)btc_socket_get_data(socket),
                          (const uint8_t *)data,
                          size);
}

static void
on_drain(btc_socket_t *socket) {
  btc_peer_on_drain((btc_peer_t *)btc_socket_get_data(socket));
}

static void
on_msg(btc_msg_t *msg, void *arg) {
  btc_peer_on_msg((btc_peer_t *)arg, msg);
}

static void
on_parse_error(void *arg) {
  btc_peer_on_parse_error((btc_peer_t *)arg);
}

/*
 * Peer
 */

static btc_peer_t *
btc_peer_create(btc_pool_t *pool) {
  btc_peer_t *peer = btc_malloc(sizeof(btc_peer_t));

  memset(peer, 0, sizeof(*peer));

  peer->pool = pool;
  peer->network = pool->network;
  peer->logger = pool->logger;
  peer->loop = pool->loop;
  peer->socket = NULL;

  if (pool->id == 0)
    pool->id++;

  peer->state = BTC_PEER_DEAD;
  peer->id = pool->id++;
  peer->version = -1;
  peer->height = -1;
  peer->relay = 1;
  peer->fee_rate = -1;
  peer->compact_mode = -1;
  peer->last_pong = -1;
  peer->last_ping = -1;
  peer->min_ping = -1;
  peer->block_time = -1;
  peer->gb_time = -1;
  peer->gh_time = -1;

  btc_parser_init(&peer->parser, peer->network->magic);

  peer->parser.on_msg = on_msg;
  peer->parser.on_error = on_parse_error;
  peer->parser.arg = peer;

  btc_inv_init(&peer->inv_queue);

  btc_filter_init(&peer->addr_filter);
  btc_filter_set(&peer->addr_filter, 5000, 0.001);

  btc_filter_init(&peer->inv_filter);
  btc_filter_set(&peer->inv_filter, 50000, 0.000001);

  btc_hashtab_init(&peer->block_map);
  btc_hashtab_init(&peer->tx_map);
  btc_hashmap_init(&peer->compact_map);

  return peer;
}

static void
btc_peer_clear_data(btc_peer_t *peer);

static void
btc_peer_destroy(btc_peer_t *peer) {
  btc_mapiter_t it;

  btc_parser_clear(&peer->parser);

  btc_peer_clear_data(peer);

  /* Free block hashes. */
  btc_map_each(&peer->block_map, it)
    btc_free(peer->block_map.keys[it]);

  /* Free TXIDs. */
  btc_map_each(&peer->tx_map, it)
    btc_free(peer->tx_map.keys[it]);

  /* Free compact blocks. */
  btc_map_each(&peer->compact_map, it)
    btc_cmpct_destroy(peer->compact_map.vals[it]);

  btc_inv_clear(&peer->inv_queue);

  btc_filter_clear(&peer->addr_filter);
  btc_filter_clear(&peer->inv_filter);

  if (peer->spv_filter != NULL)
    btc_bloom_destroy(peer->spv_filter);

  btc_hashtab_clear(&peer->block_map);
  btc_hashtab_clear(&peer->tx_map);
  btc_hashmap_clear(&peer->compact_map);

  btc_free(peer);
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
  peer->socket = socket;
  peer->addr = *addr;
  peer->outbound = 1;
  peer->time = btc_time_msec();
  peer->nonce = btc_nonces_alloc(&peer->pool->nonces);

  btc_socket_set_data(socket, peer);
  btc_socket_on_connect(socket, on_connect);
  btc_socket_on_close(socket, on_close);
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
  peer->time = btc_time_msec();
  peer->nonce = btc_nonces_alloc(&peer->pool->nonces);

  btc_socket_set_data(socket, peer);
  btc_socket_on_close(socket, on_close);
  btc_socket_on_error(socket, on_error);
  btc_socket_on_data(socket, on_data);
  btc_socket_on_drain(socket, on_drain);

  btc_peer_info(peer, "Accepted connection from %N.", &peer->addr);

  return 1;
}

static void
btc_peer_close(btc_peer_t *peer) {
  btc_socket_close(peer->socket);
  peer->state = BTC_PEER_DEAD;
  peer->parser.closed = 1;
}

static void
btc_pool_ban(btc_pool_t *pool, const btc_netaddr_t *addr);

static int
btc_peer_increase_ban(btc_peer_t *peer, int score) {
  peer->ban_score += score;

  if (peer->ban_score >= BTC_NET_BAN_SCORE) {
    btc_peer_debug(peer, "Ban threshold exceeded (%N).", &peer->addr);
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

    btc_peer_error(peer, "Write error (%N): %s", &peer->addr, msg);
    btc_peer_close(peer);

    return 0;
  }

  peer->last_send = btc_time_msec();

  return rc;
}

static int
btc_peer_send(btc_peer_t *peer, const btc_msg_t *msg) {
  size_t bodylen = btc_msg_size(msg);
  size_t length = 24 + bodylen;
  uint8_t *data = (uint8_t *)btc_malloc(length);
  uint8_t *body = data + 24;
  uint8_t *zp = data;

  /* Payload. */
  btc_msg_export(body, msg);

  /* Magic value. */
  zp = btc_uint32_write(zp, peer->network->magic);

  /* Command. */
  zp = btc_nullstr_write(zp, msg->cmd, 12);

  /* Payload length. */
  zp = btc_uint32_write(zp, bodylen);

  /* Checksum. */
  btc_uint32_write(zp, btc_checksum(body, bodylen));

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
  btc_pool_t *pool = peer->pool;
  btc_version_t msg;

  btc_version_init(&msg);

  msg.version = BTC_NET_PROTOCOL_VERSION;
  msg.services = pool->services;
  msg.time = btc_timedata_now(pool->timedata);
  msg.remote = peer->addr;

  btc_netaddr_init(&msg.local);

  msg.local.services = pool->services;
  msg.nonce = peer->nonce;

  strcpy(msg.agent, BTC_NET_USER_AGENT);

  msg.height = btc_chain_height(pool->chain);
  msg.relay = ((pool->flags & BTC_POOL_BLOCKSONLY) == 0);

  return btc_peer_sendmsg(peer, BTC_MSG_VERSION, &msg);
}

static int
btc_peer_send_verack(btc_peer_t *peer) {
  return btc_peer_sendmsg(peer, BTC_MSG_VERACK, NULL);
}

static int
btc_peer_send_ping(btc_peer_t *peer) {
  btc_ping_t ping;

  if (peer->version <= BTC_NET_PONG_VERSION) {
    ping.nonce = 0;
    return btc_peer_sendmsg(peer, BTC_MSG_PING, &ping);
  }

  if (peer->challenge != 0) {
    btc_peer_debug(peer, "Peer has not responded to ping (%N).", &peer->addr);
    return 1;
  }

  peer->last_ping = btc_time_msec();
  peer->challenge = btc_nonce();

  ping.nonce = peer->challenge;

  return btc_peer_sendmsg(peer, BTC_MSG_PING, &ping);
}

static int
btc_peer_send_pong(btc_peer_t *peer, uint64_t nonce) {
  btc_pong_t pong;

  pong.nonce = nonce;

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
  btc_addrs_t addrs;

  items[0] = (btc_netaddr_t *)addr;

  addrs.items = items;
  addrs.alloc = 0;
  addrs.length = 1;

  return btc_peer_send_addr(peer, &addrs);
}

static int
btc_peer_send_getblocks(btc_peer_t *peer,
                        const btc_vector_t *locator,
                        const uint8_t *stop) {
  const uint8_t *start = btc_hash_zero;
  btc_getblocks_t msg;

  if (locator->length > 0)
    start = locator->items[0];

  if (stop == NULL)
    stop = btc_hash_zero;

  /* Filter out duplicate requests. */
  if (btc_hash_equal(start, peer->last_start)
      && btc_hash_equal(stop, peer->last_stop)) {
    return 1;
  }

  btc_hash_copy(peer->last_start, start);
  btc_hash_copy(peer->last_stop, stop);

  msg.version = BTC_NET_PROTOCOL_VERSION;
  msg.locator = *locator;
  msg.stop = stop;

  peer->gb_time = btc_time_msec();

  btc_peer_debug(peer, "Requesting inv message from peer with getblocks (%N).",
                       &peer->addr);

  if (stop != btc_hash_zero)
    btc_peer_debug(peer, "Sending getblocks (start=%H, stop=%H).", start, stop);
  else
    btc_peer_debug(peer, "Sending getblocks (start=%H).", start);

  return btc_peer_sendmsg(peer, BTC_MSG_GETBLOCKS, &msg);
}

static int
btc_peer_send_getheaders(btc_peer_t *peer,
                         const btc_vector_t *locator,
                         const uint8_t *stop) {
  const uint8_t *start = btc_hash_zero;
  btc_getblocks_t msg;

  if (locator->length > 0)
    start = locator->items[0];

  if (stop == NULL)
    stop = btc_hash_zero;

  msg.version = BTC_NET_PROTOCOL_VERSION;
  msg.locator = *locator;
  msg.stop = stop;

  peer->gh_time = btc_time_msec();

  btc_peer_debug(peer, "Requesting headers message from peer with getheaders (%N).",
                       &peer->addr);

  btc_peer_debug(peer, "Sending getheaders (start=%H, stop=%H).", start, stop);

  return btc_peer_sendmsg(peer, BTC_MSG_GETHEADERS, &msg);
}

static int
btc_peer_send_getheaders_1(btc_peer_t *peer,
                           const uint8_t *hash,
                           const uint8_t *stop) {
  btc_vector_t locator;
  void *items[1];

  items[0] = (void *)hash;

  locator.items = items;
  locator.alloc = 0;
  locator.length = 1;

  return btc_peer_send_getheaders(peer, &locator, stop);
}

BTC_UNUSED static int
btc_peer_send_mempool(btc_peer_t *peer) {
  if (!(peer->services & BTC_NET_SERVICE_BLOOM)) {
    btc_peer_debug(peer,
      "Cannot request mempool for non-bloom peer (%N).",
      &peer->addr);
    return 1;
  }

  btc_peer_debug(peer,
    "Requesting inv message from peer with mempool (%N).",
    &peer->addr);

  return btc_peer_sendmsg(peer, BTC_MSG_MEMPOOL, NULL);
}

static int
btc_peer_send_sendcmpct(btc_peer_t *peer, uint8_t mode) {
  btc_sendcmpct_t msg;

  msg.mode = mode;

  if (peer->services & BTC_NET_SERVICE_WITNESS) {
    if (peer->version >= BTC_NET_COMPACT_WITNESS_VERSION) {
      btc_peer_info(peer, "Initializing witness compact blocks (%N).",
                          &peer->addr);

      msg.version = 2;

      return btc_peer_sendmsg(peer, BTC_MSG_SENDCMPCT, &msg);
    }
  }

#if 0
  if (peer->version >= BTC_NET_COMPACT_VERSION) {
    btc_peer_info(peer, "Initializing normal compact blocks (%N).",
                        &peer->addr);

    msg.version = 1;

    return btc_peer_sendmsg(peer, BTC_MSG_SENDCMPCT, &msg);
  }
#endif

  return 1;
}

static int
btc_peer_send_inv(btc_peer_t *peer, const btc_zinv_t *msg) {
  size_t i;

  for (i = 0; i < msg->length; i++) {
    const btc_zinvitem_t *item = &msg->items[i];

    btc_filter_add(&peer->inv_filter, item->hash, 32);
  }

  btc_peer_spam(peer, "Serving %zu inv items to %N.",
                      msg->length, &peer->addr);

  return btc_peer_sendmsg(peer, BTC_MSG_INV, msg);
}

static int
btc_peer_send_inv_0(btc_peer_t *peer,
                    enum btc_msgtype cmd,
                    uint32_t type,
                    const uint8_t *hash) {
  btc_zinvitem_t item;
  btc_zinv_t msg;

  item.type = type;
  item.hash = hash;

  msg.items = &item;
  msg.alloc = 0;
  msg.length = 1;

  return btc_peer_sendmsg(peer, cmd, &msg);
}

static int
btc_peer_send_inv_1(btc_peer_t *peer, uint32_t type, const uint8_t *hash) {
  btc_filter_add(&peer->inv_filter, hash, 32);
  btc_peer_spam(peer, "Serving 1 inv items to %N.", &peer->addr);
  return btc_peer_send_inv_0(peer, BTC_MSG_INV, type, hash);
}

static int
btc_peer_send_getdata(btc_peer_t *peer, const btc_zinv_t *msg) {
  return btc_peer_sendmsg(peer, BTC_MSG_GETDATA, msg);
}

static int
btc_peer_send_getdata_1(btc_peer_t *peer, uint32_t type, const uint8_t *hash) {
  return btc_peer_send_inv_0(peer, BTC_MSG_GETDATA, type, hash);
}

static int
btc_peer_send_notfound(btc_peer_t *peer, const btc_inv_t *msg) {
  return btc_peer_sendmsg(peer, BTC_MSG_NOTFOUND_FULL, msg);
}

static int
btc_peer_send_notfound_1(btc_peer_t *peer, uint32_t type, const uint8_t *hash) {
  return btc_peer_send_inv_0(peer, BTC_MSG_NOTFOUND, type, hash);
}

static int
btc_peer_send_headers(btc_peer_t *peer, const btc_headers_t *msg) {
  return btc_peer_sendmsg(peer, BTC_MSG_HEADERS, msg);
}

static int
btc_peer_send_headers_1(btc_peer_t *peer, const btc_header_t *hdr) {
  btc_header_t *items[1];
  btc_headers_t msg;

  items[0] = (btc_header_t *)hdr;

  msg.items = items;
  msg.alloc = 0;
  msg.length = 1;

  return btc_peer_sendmsg(peer, BTC_MSG_HEADERS, &msg);
}

static int
btc_peer_send_reject(btc_peer_t *peer, const btc_reject_t *msg) {
  btc_peer_debug(peer, "Rejecting %s %H (%N): code=%s reason=%s.",
                       msg->message,
                       msg->hash,
                       &peer->addr,
                       btc_reject_code(msg->code),
                       msg->reason);

  return btc_peer_sendmsg(peer, BTC_MSG_REJECT, msg);
}

static int
btc_peer_reject(btc_peer_t *peer,
                const char *message,
                const btc_verify_error_t *err) {
  btc_reject_t reject;

  if (err->code < BTC_REJECT_INTERNAL) {
    btc_reject_init(&reject);

    strcpy(reject.message, message);

    reject.code = err->code;

    strcpy(reject.reason, err->reason);

    btc_hash_copy(reject.hash, err->hash);

    btc_peer_send_reject(peer, &reject);
  }

  return btc_peer_increase_ban(peer, err->score);
}

static int
btc_peer_has_compact_support(btc_peer_t *peer) {
  if (peer->version < BTC_NET_COMPACT_VERSION)
    return 0;

  if (!(peer->services & BTC_NET_SERVICE_WITNESS))
    return 0;

  return peer->version >= BTC_NET_COMPACT_WITNESS_VERSION;
}

static int
btc_peer_has_compact(btc_peer_t *peer) {
  if (peer->compact_mode == -1)
    return 0;

  if (!peer->compact_witness)
    return 0;

  return 1;
}

static uint32_t
btc_peer_block_type(btc_peer_t *peer) {
  if ((peer->pool->flags & BTC_POOL_BIP152)
      && btc_peer_has_compact_support(peer)
      && btc_peer_has_compact(peer)) {
    return BTC_INV_CMPCT_BLOCK;
  }

  if (peer->services & BTC_NET_SERVICE_WITNESS)
    return BTC_INV_WITNESS_BLOCK;

  return BTC_INV_BLOCK;
}

static uint32_t
btc_peer_tx_type(btc_peer_t *peer) {
  if (peer->services & BTC_NET_SERVICE_WITNESS)
    return BTC_INV_WITNESS_TX;

  return BTC_INV_TX;
}

static int
btc_peer_get_full_block(btc_peer_t *peer, const uint8_t *hash) {
  uint32_t type = BTC_INV_BLOCK;

  if (peer->services & BTC_NET_SERVICE_WITNESS)
    type = BTC_INV_WITNESS_BLOCK;

  return btc_peer_send_getdata_1(peer, type, hash);
}

static int
btc_peer_send_merkleblock(btc_peer_t *peer, const btc_block_t *block) {
  btc_merkleblock_t mrkl;
  btc_vector_t *txs;
  int rc = 1;
  size_t i;

  btc_merkleblock_init(&mrkl);

  txs = btc_merkleblock_set_block(&mrkl, block, peer->spv_filter);

  rc &= btc_peer_sendmsg(peer, BTC_MSG_MERKLEBLOCK, &mrkl);

  for (i = 0; i < txs->length; i++)
    rc &= btc_peer_sendmsg(peer, BTC_MSG_TX_BASE, txs->items[i]);

  btc_merkleblock_clear(&mrkl);
  btc_vector_destroy(txs);

  return rc;
}

static int
btc_peer_send_cmpctblock(btc_peer_t *peer, const btc_block_t *block) {
  enum btc_msgtype type = BTC_MSG_CMPCTBLOCK_BASE;
  btc_cmpct_t msg;
  int rc;

  btc_cmpct_init(&msg);
  btc_cmpct_set_block(&msg, block, peer->compact_witness);

  if (peer->compact_witness)
    type = BTC_MSG_CMPCTBLOCK;

  rc = btc_peer_sendmsg(peer, type, &msg);

  btc_cmpct_clear(&msg);

  return rc;
}

static int
btc_peer_send_getblocktxn(btc_peer_t *peer, const btc_cmpct_t *block) {
  btc_getblocktxn_t msg;
  int rc;

  btc_getblocktxn_init(&msg);

  btc_getblocktxn_set_cmpct(&msg, block);

  rc = btc_peer_sendmsg(peer, BTC_MSG_GETBLOCKTXN, &msg);

  btc_getblocktxn_clear(&msg);

  return rc;
}

static int
btc_peer_send_blocktxn(btc_peer_t *peer,
                       const btc_block_t *block,
                       const btc_getblocktxn_t *req) {
  enum btc_msgtype type = BTC_MSG_BLOCKTXN_BASE;
  btc_blocktxn_t msg;
  int rc;

  btc_blocktxn_init(&msg);

  btc_blocktxn_set_block(&msg, block, req);

  if (peer->compact_witness)
    type = BTC_MSG_BLOCKTXN;

  rc = btc_peer_sendmsg(peer, type, &msg);

  btc_blocktxn_clear(&msg);

  return rc;
}

static int
btc_peer_flush_inv(btc_peer_t *peer) {
  btc_inv_t inv;
  int rc = 1;
  size_t i;

  if (peer->inv_queue.length == 0)
    return 1;

  btc_inv_init(&inv);
  btc_inv_grow(&inv, peer->inv_queue.length);

  for (i = 0; i < peer->inv_queue.length; i++) {
    btc_invitem_t *item = peer->inv_queue.items[i];

    if (btc_filter_has(&peer->inv_filter, item->hash, 32)) {
      btc_invitem_destroy(item);
      continue;
    }

    btc_filter_add(&peer->inv_filter, item->hash, 32);

    btc_inv_push(&inv, item);
  }

  peer->inv_queue.length = 0;

  if (inv.length > 0) {
    btc_peer_spam(peer, "Serving %zu inv items to %N.",
                        inv.length, &peer->addr);

    rc = btc_peer_sendmsg(peer, BTC_MSG_INV_FULL, &inv);
  }

  btc_inv_clear(&inv);

  return rc;
}

static int
btc_peer_announce_block(btc_peer_t *peer,
                        const btc_block_t *block,
                        const uint8_t *hash) {
  /* Don't send if they already have it. */
  if (btc_filter_has(&peer->inv_filter, hash, 32))
    return 0;

  /* Send them the block immediately if
     they're using compact block mode 1. */
  if (peer->compact_mode == 1) {
    btc_filter_add(&peer->inv_filter, hash, 32);
    btc_peer_send_cmpctblock(peer, block);
    return 1;
  }

  /* Send header for peers that request it. */
  if (peer->prefer_headers) {
    btc_filter_add(&peer->inv_filter, hash, 32);
    btc_peer_send_headers_1(peer, &block->header);
    return 1;
  }

  btc_inv_push_item(&peer->inv_queue, BTC_INV_BLOCK, hash);
  btc_peer_flush_inv(peer);

  return 1;
}

static int
btc_peer_announce_tx(btc_peer_t *peer, const btc_mpentry_t *entry) {
  /* Do not send txs to spv clients that have relay unset. */
  if (!peer->relay)
    return 0;

  /* Don't send if they already have it. */
  if (btc_filter_has(&peer->inv_filter, entry->hash, 32))
    return 0;

  /* Check the peer's bloom filter. */
  if (peer->spv_filter != NULL) {
    if (!btc_tx_matches(entry->tx, peer->spv_filter))
      return 0;
  }

  /* Check the fee filter. */
  if (peer->fee_rate != -1) {
    int64_t rate = btc_get_rate(entry->fee, entry->size);

    if (rate < peer->fee_rate)
      return 0;
  }

  btc_inv_push_item(&peer->inv_queue, BTC_INV_TX, entry->hash);

  if (peer->inv_queue.length >= 500)
    btc_peer_flush_inv(peer);

  return 1;
}

static void
btc_pool_on_connect(btc_pool_t *pool, btc_peer_t *peer);

static void
btc_peer_on_connect(btc_peer_t *peer) {
  if (peer->outbound) {
    /* Say hello. */
    btc_peer_send_version(peer);
  } else {
    /* We're shy. Wait for an introduction. */
  }

  peer->state = BTC_PEER_WAIT_VERSION;
  peer->time = btc_time_msec();

  btc_pool_on_connect(peer->pool, peer);
}

static void
btc_pool_on_close(btc_pool_t *pool, btc_peer_t *peer);

static void
btc_peer_on_close(btc_peer_t *peer) {
  btc_pool_on_close(peer->pool, peer);
}

static void
btc_pool_on_complete(btc_pool_t *pool, btc_peer_t *peer);

static void
btc_peer_on_version(btc_peer_t *peer, const btc_version_t *msg) {
  if (peer->state != BTC_PEER_WAIT_VERSION) {
    btc_peer_debug(peer, "Peer sent unsolicited version (%N).", &peer->addr);
    btc_peer_close(peer);
    return;
  }

  peer->version = msg->version;
  peer->services = msg->services;
  peer->height = msg->height;
  strcpy(peer->agent, msg->agent);
  peer->relay = msg->relay;
  peer->local = msg->remote;

  if (!peer->network->self_connect) {
    if (btc_nonces_has(&peer->pool->nonces, msg->nonce)) {
      btc_peer_warn(peer, "We connected to ourself. Oops (%N).", &peer->addr);
      btc_peer_close(peer);
      return;
    }
  }

  if (peer->version < BTC_NET_MIN_VERSION) {
    btc_peer_debug(peer, "Peer does not support required protocol version (%N).",
                         &peer->addr);
    btc_peer_close(peer);
    return;
  }

  if (peer->outbound) {
    if ((peer->services & BTC_NET_SERVICE_NETWORK) == 0) {
      btc_peer_debug(peer, "Peer does not support network services (%N).",
                           &peer->addr);
      btc_peer_close(peer);
      return;
    }

    if (peer->pool->flags & BTC_POOL_CHECKPOINTS) {
      if (peer->version < BTC_NET_HEADERS_VERSION) {
        btc_peer_debug(peer, "Peer does not support getheaders (%N).",
                             &peer->addr);
        btc_peer_close(peer);
        return;
      }
    }

    if ((peer->services & BTC_NET_SERVICE_WITNESS) == 0) {
      btc_peer_debug(peer, "Peer does not support segregated witness (%N).",
                           &peer->addr);
      btc_peer_close(peer);
      return;
    }

    if (peer->pool->flags & BTC_POOL_BIP152) {
      if (!btc_peer_has_compact_support(peer)) {
        btc_peer_debug(peer, "Peer does not support compact blocks (%N).",
                             &peer->addr);
      }
    }
  }

  if (!peer->outbound)
    btc_peer_send_version(peer);

  btc_peer_send_verack(peer);

  peer->state = BTC_PEER_WAIT_VERACK;
}

static void
btc_peer_on_verack(btc_peer_t *peer) {
  if (peer->state != BTC_PEER_WAIT_VERACK) {
    btc_peer_debug(peer, "Peer sent unsolicited verack (%N).", &peer->addr);
    btc_peer_close(peer);
    return;
  }

  peer->state = BTC_PEER_CONNECTED;

  btc_peer_debug(peer, "Version handshake complete (%N).", &peer->addr);
  btc_pool_on_complete(peer->pool, peer);
}

static void
btc_peer_on_ping(btc_peer_t *peer, const btc_ping_t *msg) {
  if (msg->nonce == 0)
    return;

  btc_peer_send_pong(peer, msg->nonce);
}

static void
btc_peer_on_pong(btc_peer_t *peer, const btc_pong_t *msg) {
  int64_t now = btc_time_msec();

  if (peer->challenge == 0) {
    btc_peer_debug(peer, "Peer sent an unsolicited pong (%N).", &peer->addr);
    return;
  }

  if (msg->nonce != peer->challenge) {
    if (msg->nonce == 0) {
      btc_peer_debug(peer, "Peer sent a zero nonce (%N).", &peer->addr);
      peer->challenge = 0;
      return;
    }
    btc_peer_debug(peer, "Peer sent the wrong nonce (%N).", &peer->addr);
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
    btc_peer_debug(peer, "Timing mismatch (what?) (%N).", &peer->addr);
  }

  peer->challenge = 0;
}

static void
btc_peer_on_sendheaders(btc_peer_t *peer) {
  if (peer->prefer_headers) {
    btc_peer_debug(peer, "Peer sent a duplicate sendheaders (%N).",
                         &peer->addr);
    return;
  }

  peer->prefer_headers = 1;
}

static void
btc_peer_on_filterload(btc_peer_t *peer, const btc_bloom_t *filter) {
  btc_pool_t *pool = peer->pool;

  if (!(pool->flags & BTC_POOL_BIP37)) {
    btc_peer_debug(peer, "Peer loaded filter without bip37 enabled (%N).",
                         &peer->addr);
    btc_peer_close(peer);
    return;
  }

  if (!btc_bloom_is_within_constraints(filter)) {
    btc_peer_increase_ban(peer, 100);
    return;
  }

  /* Could avoid a second allocation here. */
  if (peer->spv_filter == NULL)
    peer->spv_filter = btc_bloom_clone(filter);
  else
    btc_bloom_copy(peer->spv_filter, filter);

  peer->relay = 1;
}

static void
btc_peer_on_filteradd(btc_peer_t *peer, const btc_filteradd_t *msg) {
  btc_pool_t *pool = peer->pool;

  if (!(pool->flags & BTC_POOL_BIP37)) {
    btc_peer_debug(peer, "Peer added to filter without bip37 enabled (%N).",
                         &peer->addr);
    btc_peer_close(peer);
    return;
  }

  if (msg->length > BTC_MAX_SCRIPT_PUSH) {
    btc_peer_increase_ban(peer, 100);
    return;
  }

  if (peer->spv_filter != NULL)
    btc_bloom_add(peer->spv_filter, msg->data, msg->length);

  peer->relay = 1;
}

static void
btc_peer_on_filterclear(btc_peer_t *peer) {
  btc_pool_t *pool = peer->pool;

  if (!(pool->flags & BTC_POOL_BIP37)) {
    btc_peer_debug(peer, "Peer cleared filter without bip37 enabled (%N).",
                         &peer->addr);
    btc_peer_close(peer);
    return;
  }

  if (peer->spv_filter != NULL)
    btc_bloom_reset(peer->spv_filter);

  peer->relay = 1;
}

static void
btc_peer_on_feefilter(btc_peer_t *peer, const btc_feefilter_t *msg) {
  if (msg->rate < 0 || msg->rate > BTC_MAX_MONEY) {
    btc_peer_increase_ban(peer, 100);
    return;
  }

  peer->fee_rate = msg->rate;
}

static void
btc_peer_on_sendcmpct(btc_peer_t *peer, const btc_sendcmpct_t *msg) {
  if (peer->compact_mode != -1) {
    btc_peer_debug(peer, "Peer sent a duplicate sendcmpct (%N).", &peer->addr);
    return;
  }

  if (msg->version > 2) {
    /* Ignore. */
    btc_peer_info(peer, "Peer requested compact blocks version %llu (%N).",
                        msg->version, &peer->addr);
    return;
  }

  if (msg->mode > 1) {
    /* Ignore. */
    btc_peer_info(peer, "Peer requested compact blocks mode %hhu (%N).",
                        msg->mode, &peer->addr);
    return;
  }

  btc_peer_info(peer,
    "Peer initialized compact blocks (mode=%hhu, version=%llu) (%N).",
    msg->mode, msg->version, &peer->addr);

  peer->compact_mode = msg->mode;
  peer->compact_witness = (msg->version == 2);
}

static void
btc_peer_on_error(btc_peer_t *peer, const char *msg) {
  btc_peer_error(peer, "Socket error (%N): %s", &peer->addr, msg);
  btc_peer_close(peer);
}

static int
btc_peer_on_data(btc_peer_t *peer, const uint8_t *data, size_t size) {
  if (peer->state == BTC_PEER_DEAD)
    return 0;

  if (size == 0) {
    btc_peer_error(peer, "Socket hangup (%N).", &peer->addr);
    btc_peer_close(peer);
    return 0;
  }

  peer->last_recv = btc_time_msec();

  return !btc_parser_feed(&peer->parser, data, size);
}

static int
btc_peer_flush_data(btc_peer_t *peer);

static void
btc_peer_on_drain(btc_peer_t *peer) {
  if (peer->state == BTC_PEER_DEAD)
    return;

  btc_peer_flush_data(peer);
}

static void
btc_pool_on_msg(btc_pool_t *pool, btc_peer_t *peer, btc_msg_t *msg);

static void
btc_peer_on_msg(btc_peer_t *peer, btc_msg_t *msg) {
  if (peer->state == BTC_PEER_DEAD)
    return;

  switch (msg->type) {
    case BTC_MSG_VERSION:
      btc_peer_on_version(peer, (const btc_version_t *)msg->body);
      break;
    case BTC_MSG_VERACK:
      btc_peer_on_verack(peer);
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
    case BTC_MSG_FILTERLOAD:
      btc_peer_on_filterload(peer, (const btc_bloom_t *)msg->body);
      break;
    case BTC_MSG_FILTERADD:
      btc_peer_on_filteradd(peer, (const btc_filteradd_t *)msg->body);
      break;
    case BTC_MSG_FILTERCLEAR:
      btc_peer_on_filterclear(peer);
      break;
    case BTC_MSG_FEEFILTER:
      btc_peer_on_feefilter(peer, (const btc_feefilter_t *)msg->body);
      break;
    case BTC_MSG_SENDCMPCT:
      btc_peer_on_sendcmpct(peer, (const btc_sendcmpct_t *)msg->body);
      break;
    default:
      break;
  }

  btc_pool_on_msg(peer->pool, peer, msg);
}

static void
btc_peer_on_parse_error(btc_peer_t *peer) {
  if (peer->state == BTC_PEER_DEAD)
    return;

  btc_peer_error(peer, "Parse error (%N).", &peer->addr);
  btc_peer_increase_ban(peer, 10);
}

static int
btc_peer_flush_data(btc_peer_t *peer) {
  btc_pool_t *pool = peer->pool;
  btc_chain_t *chain = pool->chain;
  btc_mempool_t *mempool = pool->mempool;
  btc_invitem_t *item, *next;
  int blk_count = 0;
  int tx_count = 0;
  int cmpct_count = 0;
  int64_t unknown = -1;
  uint32_t type;
  btc_inv_t nf;
  int send_tip;
  size_t size;
  int ret = 1;

  if (peer->state != BTC_PEER_CONNECTED)
    return 1;

  if (peer->sending.length == 0)
    return 1;

  btc_inv_init(&nf);

  for (item = peer->sending.head; item != NULL; item = next) {
    next = item->next;
    size = btc_socket_buffered(peer->socket) + nf.length * 36;
    type = item->type;

    if (size >= (10 << 20) || peer->state == BTC_PEER_DEAD) {
      /* Wait for the peer to read
         before we pull more data
         out of the database. */
      ret = 0;
      break;
    }

    /* Check the hashContinue early. */
    send_tip = btc_hash_equal(item->hash, peer->hash_continue);

    /* Maybe fall back to full block. */
    if (type == BTC_INV_CMPCT_BLOCK) {
      const btc_entry_t *entry = btc_chain_by_hash(chain, item->hash);

      if (entry != NULL && entry->height < btc_chain_height(chain) - 10)
        type = peer->compact_witness ? BTC_INV_WITNESS_BLOCK : BTC_INV_BLOCK;
    }

    switch (type) {
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

      case BTC_INV_CMPCT_BLOCK: {
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

        btc_peer_send_cmpctblock(peer, block);

        btc_block_destroy(block);
        btc_invitem_destroy(item);

        blk_count += 1;
        cmpct_count += 1;

        break;
      }

      case BTC_INV_FILTERED_BLOCK: {
        const btc_entry_t *entry;
        btc_block_t *block;

        if (!(pool->flags & BTC_POOL_BIP37)) {
          btc_peer_debug(peer, "Peer requested a merkleblock without bip37 enabled (%N).",
                               &peer->addr);
          btc_peer_close(peer);
          break;
        }

        if (peer->spv_filter == NULL) {
          btc_inv_push(&nf, item);
          break;
        }

        entry = btc_chain_by_hash(chain, item->hash);

        if (entry == NULL) {
          btc_inv_push(&nf, item);
          break;
        }

        block = btc_chain_get_block(chain, entry);

        if (block == NULL) {
          btc_inv_push(&nf, item);
          break;
        }

        btc_peer_send_merkleblock(peer, block);

        btc_block_destroy(block);
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

        if (type == BTC_INV_TX)
          btc_peer_sendmsg(peer, BTC_MSG_TX_BASE, entry->tx);
        else
          btc_peer_sendmsg(peer, BTC_MSG_TX, entry->tx);

        btc_invitem_destroy(item);

        tx_count += 1;

        break;
      }

      default: {
        btc_inv_push(&nf, item);
        unknown = type;
        break;
      }
    }

    if (send_tip) {
      btc_peer_send_inv_1(peer, BTC_INV_BLOCK, btc_chain_tip(chain)->hash);
      btc_hash_init(peer->hash_continue);
    }

    peer->sending.head = next;
    peer->sending.length--;

    if (peer->sending.head == NULL)
      peer->sending.tail = NULL;
  }

  if (nf.length > 0)
    btc_peer_send_notfound(peer, &nf);

  if (blk_count > 0) {
    btc_pool_debug(pool,
      "Served %d blocks with getdata (notfound=%zu, cmpct=%d) (%N).",
      blk_count, nf.length, cmpct_count, &peer->addr);
  }

  if (tx_count > 0) {
    btc_pool_debug(pool, "Served %d txs with getdata (notfound=%zu) (%N).",
                         tx_count, nf.length, &peer->addr);
  }

  if (unknown != -1) {
    btc_pool_debug(pool, "Peer sent an unknown getdata type: %u (%N).",
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
btc_peer_maybe_timeout(btc_peer_t *peer, int64_t now) {
  btc_chain_t *chain = peer->pool->chain;

  if (!btc_chain_synced(chain)) {
    if (peer->gb_time != -1 && now > peer->gb_time + 30000) {
      btc_peer_error(peer, "Peer is stalling (inv) (%N).", &peer->addr);
      btc_peer_close(peer);
      return;
    }
  }

  if (peer->gh_time != -1 && now > peer->gh_time + 60000) {
    btc_peer_error(peer, "Peer is stalling (headers) (%N).", &peer->addr);
    btc_peer_close(peer);
    return;
  }

  if (peer->syncing && peer->loader && !btc_chain_synced(chain)) {
    if (now > peer->block_time + 120000) {
      btc_peer_error(peer, "Peer is stalling (block) (%N).", &peer->addr);
      btc_peer_close(peer);
      return;
    }
  }

  if (btc_chain_synced(chain) || !peer->syncing) {
    btc_mapiter_t it;

    btc_map_each(&peer->block_map, it) {
      int64_t ts = peer->block_map.vals[it];

      if (now > ts + 120000) {
        btc_peer_error(peer, "Peer is stalling (block) (%N).", &peer->addr);
        btc_peer_close(peer);
        return;
      }
    }

    btc_map_each(&peer->tx_map, it) {
      int64_t ts = peer->tx_map.vals[it];

      if (now > ts + 120000) {
        btc_peer_error(peer, "Peer is stalling (tx) (%N).", &peer->addr);
        btc_peer_close(peer);
        return;
      }
    }

    btc_map_each(&peer->compact_map, it) {
      btc_cmpct_t *block = peer->compact_map.vals[it];

      if (now > block->now + 30000) {
        btc_peer_error(peer, "Peer is stalling (blocktxn) (%N).", &peer->addr);
        btc_peer_close(peer);
        return;
      }
    }
  }

  if (now > peer->time + 60000) {
    int mult = (peer->version <= BTC_NET_PONG_VERSION ? 4 : 1);

    if (peer->last_recv == 0 || peer->last_send == 0) {
      btc_peer_error(peer, "Peer is stalling (no message) (%N).", &peer->addr);
      btc_peer_close(peer);
      return;
    }

    if (now > peer->last_send + 20 * 60000) {
      btc_peer_error(peer, "Peer is stalling (send) (%N).", &peer->addr);
      btc_peer_close(peer);
      return;
    }

    if (now > peer->last_recv + 20 * 60000 * mult) {
      btc_peer_error(peer, "Peer is stalling (recv) (%N).", &peer->addr);
      btc_peer_close(peer);
      return;
    }

    if (peer->challenge && now > peer->last_ping + 20 * 60000) {
      btc_peer_error(peer, "Peer is stalling (ping) (%N).", &peer->addr);
      btc_peer_close(peer);
      return;
    }
  }
}

static void
btc_peer_on_tick(btc_peer_t *peer, int64_t now) {
  if (peer->state == BTC_PEER_DEAD)
    return;

  if (peer->state != BTC_PEER_CONNECTED) {
    if (now > peer->time + 5000) {
      btc_peer_debug(peer, "Peer stalled (connect) (%N).", &peer->addr);
      btc_peer_close(peer);
      return;
    }
    return;
  }

  if (now >= peer->ping_timer + 30000) {
    btc_peer_send_ping(peer);
    peer->ping_timer = now;
  }

  if (now >= peer->inv_timer + 5000) {
    btc_peer_flush_inv(peer);
    peer->inv_timer = now;
  }

  if (now >= peer->stall_timer + 5000) {
    btc_peer_maybe_timeout(peer, now);
    peer->stall_timer = now;
  }

  btc_peer_flush_data(peer);

  if (btc_socket_buffered(peer->socket) > (30 << 20)) {
    btc_peer_error(peer, "Peer stalled (drain) (%N).", &peer->addr);
    btc_peer_close(peer);
    return;
  }
}

/**
 * Peer List
 */

static void
btc_peers_init(btc_peers_t *list) {
  btc_netmap_init(&list->map); /* addr->peer */
  btc_intmap_init(&list->ids); /* id->peer */

  list->head = NULL;
  list->tail = NULL;
  list->load = NULL;
  list->inbound = 0;
  list->outbound = 0;
  list->length = 0;
}

static void
btc_peers_clear(btc_peers_t *list) {
  btc_netmap_clear(&list->map);
  btc_intmap_clear(&list->ids);
}

static void
btc_peers_add(btc_peers_t *list, btc_peer_t *peer) {
  CHECK(btc_netmap_put(&list->map, &peer->addr, peer));
  CHECK(btc_intmap_put(&list->ids, peer->id, peer));

  btc_list_push(list, peer, btc_peer_t);

  if (peer->outbound)
    list->outbound += 1;
  else
    list->inbound += 1;
}

static void
btc_peers_remove(btc_peers_t *list, btc_peer_t *peer) {
  CHECK(btc_netmap_del(&list->map, &peer->addr) == &peer->addr);
  CHECK(btc_intmap_del(&list->ids, peer->id) == peer->id);

  btc_list_remove(list, peer, btc_peer_t);

  if (peer == list->load) {
    CHECK(peer->loader == 1);
    peer->loader = 0;
    list->load = NULL;
  }

  if (peer->outbound)
    list->outbound -= 1;
  else
    list->inbound -= 1;
}

static int
btc_peers_has(btc_peers_t *list, const btc_netaddr_t *addr) {
  return btc_netmap_has(&list->map, addr);
}

static btc_peer_t *
btc_peers_get(btc_peers_t *list, const btc_netaddr_t *addr) {
  return btc_netmap_get(&list->map, addr);
}

static btc_peer_t *
btc_peers_find(btc_peers_t *list, uint32_t id) {
  return btc_intmap_get(&list->ids, id);
}

static void
btc_peers_close(btc_peers_t *list) {
  btc_peer_t *peer;

  for (peer = list->head; peer != NULL; peer = peer->next)
    btc_peer_close(peer);
}

/*
 * Header Node
 */

static btc_hdrnode_t *
btc_hdrnode_create(const uint8_t *hash, int32_t height) {
  btc_hdrnode_t *node = btc_malloc(sizeof(btc_hdrnode_t));

  btc_hash_copy(node->hash, hash);

  node->height = height;
  node->next = NULL;

  return node;
}

static void
btc_hdrnode_destroy(btc_hdrnode_t *node) {
  btc_free(node);
}

/*
 * Pool
 */

btc_pool_t *
btc_pool_create(const btc_network_t *network,
                btc_loop_t *loop,
                btc_chain_t *chain,
                btc_mempool_t *mempool) {
  btc_pool_t *pool = btc_malloc(sizeof(btc_pool_t));

  memset(pool, 0, sizeof(*pool));

  pool->network = network;
  pool->loop = loop;
  pool->logger = NULL;
  pool->timedata = NULL;
  pool->addrman = btc_addrman_create(network);
  pool->chain = chain;
  pool->mempool = mempool;
  pool->flags = BTC_POOL_DEFAULT_FLAGS;
  pool->services = BTC_NET_LOCAL_SERVICES;
  pool->port = network->port;
  btc_vector_init(&pool->bind);
  btc_vector_init(&pool->connect);
  btc_sockaddr_import(&pool->proxy, "0.0.0.0", 0);
  pool->max_inbound = 128;
  pool->max_outbound = 8;
  pool->only_net = BTC_IPNET_NONE;
  pool->server = btc_server_create(loop);
  btc_peers_init(&pool->peers);
  btc_nonces_init(&pool->nonces);
  btc_hashset_init(&pool->block_map);
  btc_hashset_init(&pool->tx_map);
  btc_hashset_init(&pool->compact_map);
  pool->block_mode = 0;
  pool->checkpoints = 0;
  pool->header_tip = NULL;
  pool->header_head = NULL;
  pool->header_tail = NULL;
  pool->header_next = NULL;
  pool->refill_timer = 0;
  pool->flush_timer = 0;
  pool->id = 0;
  pool->required_services = BTC_NET_LOCAL_SERVICES;
  pool->synced = 0;

  btc_server_set_data(pool->server, pool);
  btc_server_on_socket(pool->server, on_server_socket);

  return pool;
}

void
btc_pool_destroy(btc_pool_t *pool) {
  size_t i;

  for (i = 0; i < pool->bind.length; i++)
    btc_free(pool->bind.items[i]);

  for (i = 0; i < pool->connect.length; i++)
    btc_netaddr_destroy(pool->connect.items[i]);

  btc_addrman_destroy(pool->addrman);
  btc_vector_clear(&pool->bind);
  btc_vector_clear(&pool->connect);
  btc_server_destroy(pool->server);
  btc_peers_clear(&pool->peers);
  btc_nonces_clear(&pool->nonces);
  btc_hashset_clear(&pool->block_map);
  btc_hashset_clear(&pool->tx_map);
  btc_hashset_clear(&pool->compact_map);
  btc_free(pool);
}

void
btc_pool_set_logger(btc_pool_t *pool, btc_logger_t *logger) {
  pool->logger = logger;
  btc_addrman_set_logger(pool->addrman, logger);
}

void
btc_pool_set_timedata(btc_pool_t *pool, btc_timedata_t *td) {
  pool->timedata = td;
  btc_addrman_set_timedata(pool->addrman, td);
}

void
btc_pool_set_port(btc_pool_t *pool, int port) {
  CHECK(port > 0 && port <= 0xffff);
  pool->port = port;
}

void
btc_pool_set_bind(btc_pool_t *pool, const btc_netaddr_t *addr) {
  btc_sockaddr_t *sa = btc_malloc(sizeof(btc_sockaddr_t));

  btc_netaddr_get_sockaddr(sa, addr);

  btc_vector_push(&pool->bind, sa);

  btc_addrman_add_local(pool->addrman, addr, BTC_SCORE_BIND);
}

void
btc_pool_set_external(btc_pool_t *pool, const btc_netaddr_t *addr) {
  btc_addrman_add_local(pool->addrman, addr, BTC_SCORE_MANUAL);
}

void
btc_pool_set_connect(btc_pool_t *pool, const btc_netaddr_t *addr) {
  btc_vector_push(&pool->connect, btc_netaddr_clone(addr));
}

void
btc_pool_set_proxy(btc_pool_t *pool, const btc_netaddr_t *addr) {
  btc_netaddr_get_sockaddr(&pool->proxy, addr);
  btc_addrman_set_proxy(pool->addrman, addr);
}

void
btc_pool_set_maxinbound(btc_pool_t *pool, size_t max_inbound) {
  pool->max_inbound = max_inbound;
}

void
btc_pool_set_maxoutbound(btc_pool_t *pool, size_t max_outbound) {
  pool->max_outbound = max_outbound;
}

void
btc_pool_set_bantime(btc_pool_t *pool, int64_t ban_time) {
  btc_addrman_set_bantime(pool->addrman, ban_time);
}

void
btc_pool_set_onlynet(btc_pool_t *pool, enum btc_ipnet only_net) {
  pool->only_net = only_net;
}

static int
btc_pool_listen(btc_pool_t *pool) {
  size_t i;

  if (pool->bind.length == 0) {
    if (!btc_server_listen_external(pool->server, pool->port)) {
      const char *msg = btc_server_strerror(pool->server);

      btc_pool_error(pool, "Could not listen on port %d: %s.", pool->port, msg);

      btc_server_close(pool->server);

      return 0;
    }

    btc_pool_info(pool, "Listening on port %d.", pool->port);

    return 1;
  }

  for (i = 0; i < pool->bind.length; i++) {
    btc_sockaddr_t *addr = pool->bind.items[i];

    if (addr->port == 0)
      addr->port = pool->port;

    if (!btc_server_listen(pool->server, addr)) {
      const char *msg = btc_server_strerror(pool->server);

      btc_pool_error(pool, "Could not listen on %S: %s.", addr, msg);

      btc_server_close(pool->server);

      return 0;
    }

    btc_pool_info(pool, "Listening on %S.", addr);
  }

  return 1;
}

static void
btc_pool_discover_local(btc_pool_t *pool) {
  btc_sockaddr_t *res, *it;
  btc_netaddr_t addr;

  btc_pool_info(pool, "Looking up local addresses...");

  if (btc_getifaddrs(&res, pool->port)) {
    int total = 0;

    for (it = res; it != NULL; it = it->next) {
      btc_netaddr_set_sockaddr(&addr, it);

      btc_pool_info(pool, "Local address found: %N.", &addr);

      btc_addrman_add_local(pool->addrman, &addr, BTC_SCORE_IF);

      total += 1;
    }

    btc_pool_info(pool, "Found %d local addresses.", total);

    btc_freeifaddrs(res);
  } else {
    btc_pool_debug(pool, "Local addresses not found.");
  }
}

static void
btc_pool_discover_external(btc_pool_t *pool) {
  btc_sockaddr_t sa;
  btc_netaddr_t na;

  btc_pool_info(pool, "Looking up IPv4 address...");

  if (btc_net_external(&sa, BTC_AF_INET, pool->port)) {
    btc_pool_info(pool, "IPv4 address found: %S.", &sa);
    btc_netaddr_set_sockaddr(&na, &sa);
    btc_addrman_add_local(pool->addrman, &na, BTC_SCORE_DNS);
  } else {
    btc_pool_debug(pool, "IPv4 address not found.");
  }

  btc_pool_info(pool, "Looking up IPv6 address...");

  if (btc_net_external(&sa, BTC_AF_INET6, pool->port)) {
    btc_pool_info(pool, "IPv6 address found: %S.", &sa);
    btc_netaddr_set_sockaddr(&na, &sa);
    btc_addrman_add_local(pool->addrman, &na, BTC_SCORE_DNS);
  } else {
    btc_pool_debug(pool, "IPv6 address not found.");
  }
}

static const btc_checkpoint_t *
btc_pool_next_tip(btc_pool_t *pool, int32_t height) {
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
btc_pool_clear_chain(btc_pool_t *pool) {
  btc_hdrnode_t *node, *next;

  for (node = pool->header_head; node != NULL; node = next) {
    next = node->next;
    btc_hdrnode_destroy(node);
  }

  pool->checkpoints = 0;
  pool->header_tip = NULL;
  pool->header_head = NULL;
  pool->header_tail = NULL;
  pool->header_next = NULL;
}

static void
btc_pool_reset_chain(btc_pool_t *pool) {
  const btc_network_t *network = pool->network;
  const btc_entry_t *tip;

  if (!(pool->flags & BTC_POOL_CHECKPOINTS))
    return;

  if (network->checkpoints.length == 0)
    return;

  btc_pool_clear_chain(pool);

  tip = btc_chain_tip(pool->chain);

  if (tip->height < network->last_checkpoint) {
    pool->checkpoints = 1;
    pool->header_tip = btc_pool_next_tip(pool, tip->height);
    pool->header_head = btc_hdrnode_create(tip->hash, tip->height);
    pool->header_tail = pool->header_head;

    btc_pool_info(pool, "Initialized header chain to height %d (checkpoint=%H).",
                        tip->height, pool->header_tip->hash);
  }
}

int
btc_pool_open(btc_pool_t *pool, const char *prefix, unsigned int flags) {
  char file[BTC_PATH_MAX];

  pool->flags = flags;
  pool->services = BTC_NET_LOCAL_SERVICES;

  if (pool->flags & BTC_POOL_BIP37)
    pool->services |= BTC_NET_SERVICE_BLOOM;

  btc_pool_info(pool, "Opening pool.");

  btc_fs_mkdir(prefix);

  if (!btc_path_join(file, sizeof(file), prefix, "peers.dat"))
    return 0;

  if (!btc_addrman_open(pool->addrman, file, flags))
    return 0;

  if (pool->flags & BTC_POOL_LISTEN) {
    if (!btc_pool_listen(pool)) {
      btc_addrman_close(pool->addrman);
      return 0;
    }

    if (pool->flags & BTC_POOL_DISCOVER) {
      btc_pool_discover_local(pool);
      btc_pool_discover_external(pool);
    }
  }

  pool->synced = btc_chain_synced(pool->chain);

  btc_pool_reset_chain(pool);

  btc_loop_on_tick(pool->loop, on_tick, pool);

  return 1;
}

void
btc_pool_close(btc_pool_t *pool) {
  btc_pool_info(pool, "Closing pool.");

  btc_loop_off_tick(pool->loop, on_tick, pool);

  btc_server_close(pool->server);
  btc_peers_close(&pool->peers);
  btc_pool_clear_chain(pool);
  btc_addrman_close(pool->addrman);
}

static const btc_netaddr_t *
btc_pool_get_addr(btc_pool_t *pool) {
  int64_t now = btc_timedata_now(pool->timedata);
  const btc_addrent_t *entry;
  const btc_netaddr_t *addr;
  size_t i;

  if (pool->flags & BTC_POOL_CONNECT) {
    for (i = 0; i < pool->connect.length; i++) {
      addr = pool->connect.items[i];

      if (btc_peers_has(&pool->peers, addr))
        continue;

      return addr;
    }

    return NULL;
  }

  for (i = 0; i < 100; i++) {
    entry = btc_addrman_get(pool->addrman);

    if (entry == NULL)
      break;

    addr = &entry->addr;

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

    if (!(pool->flags & BTC_POOL_ONION)) {
      if (btc_netaddr_is_onion(addr))
        continue;
    }

    if (i < 30 && now - entry->last_attempt < 600)
      continue;

    if (i < 50 && addr->port != pool->network->port)
      continue;

    if (pool->only_net != BTC_IPNET_NONE) {
      if (btc_netaddr_network(addr) != pool->only_net)
        continue;
    }

    return addr;
  }

  return NULL;
}

static void
btc_pool_ban(btc_pool_t *pool, const btc_netaddr_t *addr) {
  btc_peer_t *peer = btc_peers_get(&pool->peers, addr);

  btc_pool_debug(pool, "Banning peer (%N).", addr);

  btc_addrman_ban(pool->addrman, addr);
  btc_addrman_remove(pool->addrman, addr);

  if (peer != NULL)
    btc_peer_close(peer);
}

static btc_peer_t *
btc_pool_create_outbound(btc_pool_t *pool, const btc_netaddr_t *addr) {
  btc_peer_t *peer = btc_peer_create(pool);

  btc_addrman_mark_attempt(pool->addrman, addr);

  btc_pool_debug(pool, "Connecting to %N.", addr);

  if (!btc_peer_open(peer, addr)) {
    const char *msg = btc_loop_strerror(pool->loop);

    btc_pool_debug(pool, "Connection failed: %s (%N).", msg, addr);
    btc_peer_destroy(peer);

    return NULL;
  }

  return peer;
}

static int
btc_pool_add_outbound(btc_pool_t *pool) {
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
btc_pool_is_syncable(btc_pool_t *pool, btc_peer_t *peer) {
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
btc_pool_send_locator(btc_pool_t *pool,
                      btc_peer_t *peer,
                      const btc_vector_t *locator) {
  if (!btc_pool_is_syncable(pool, peer))
    return 0;

  /* Ask for the mempool if we're synced. */
  if (pool->network->request_mempool) {
    if (peer->loader && btc_chain_synced(pool->chain))
      btc_peer_send_mempool(peer);
  }

  peer->syncing = 1;
  peer->block_time = btc_time_msec();

  if (pool->checkpoints) {
    btc_peer_send_getheaders(peer, locator, pool->header_tip->hash);
    return 1;
  }

  btc_peer_send_getblocks(peer, locator, NULL);

  return 1;
}

static int
btc_pool_send_sync(btc_pool_t *pool, btc_peer_t *peer) {
  btc_vector_t locator;

  if (peer->syncing)
    return 0;

  if (!btc_pool_is_syncable(pool, peer))
    return 0;

  btc_vector_init(&locator);
  btc_chain_get_locator(pool->chain, &locator, NULL);
  btc_pool_send_locator(pool, peer, &locator);
  btc_vector_clear(&locator);

  return 1;
}

static void
btc_pool_set_loader(btc_pool_t *pool, btc_peer_t *peer) {
  CHECK(peer->outbound == 1);
  CHECK(pool->peers.load == NULL);
  CHECK(peer->loader == 0);

  peer->loader = 1;
  pool->peers.load = peer;

  btc_pool_send_sync(pool, peer);
}

static int
btc_pool_add_loader(btc_pool_t *pool) {
  const btc_netaddr_t *addr;
  btc_peer_t *peer;

  CHECK(pool->peers.load == NULL);

  for (peer = pool->peers.head; peer != NULL; peer = peer->next) {
    if (!peer->outbound)
      continue;

    btc_pool_info(pool, "Repurposing peer for loader (%N).", &peer->addr);

    btc_pool_set_loader(pool, peer);

    return 1;
  }

  addr = btc_pool_get_addr(pool);

  if (addr == NULL)
    return 0;

  peer = btc_pool_create_outbound(pool, addr);

  if (peer == NULL)
    return 0;

  btc_pool_info(pool, "Adding loader peer (%N).", &peer->addr);

  btc_peers_add(&pool->peers, peer);

  btc_pool_set_loader(pool, peer);

  return 1;
}

static int
btc_pool_fill_outbound(btc_pool_t *pool) {
  size_t i, total, need;

  if (pool->peers.load == NULL) {
    if (!btc_pool_add_loader(pool))
      return 0;
  }

  if (pool->peers.outbound >= pool->max_outbound)
    return 1;

  need = pool->max_outbound - pool->peers.outbound;
  total = btc_addrman_total(pool->addrman);

  if (pool->flags & BTC_POOL_CONNECT)
    total = pool->connect.length;

  if (need > total)
    need = total;

  if (need == 0)
    return 0;

  btc_pool_debug(pool, "Refilling %zu peers (%zu/%zu).", need,
                 pool->peers.outbound, pool->max_outbound);

  for (i = 0; i < need; i++)
    btc_pool_add_outbound(pool);

  return 1;
}

static void
btc_pool_on_tick(btc_pool_t *pool, int64_t now) {
  if (now >= pool->refill_timer + 3000) {
    btc_pool_fill_outbound(pool);
    pool->refill_timer = now;
  }

  if (now >= pool->flush_timer + 10 * 60 * 1000) {
    btc_addrman_flush(pool->addrman);
    pool->flush_timer = now;
  }
}

static void
btc_pool_on_socket(btc_pool_t *pool, btc_socket_t *socket) {
  btc_sockaddr_t sa;
  btc_netaddr_t na;
  btc_peer_t *peer;

  btc_socket_address(&sa, socket);

  if (pool->peers.length >= pool->max_inbound) {
    btc_pool_debug(pool, "Ignoring inbound peer (%S).", &sa);
    btc_socket_close(socket);
    return;
  }

  btc_netaddr_set_sockaddr(&na, &sa);

  if (btc_addrman_is_banned(pool->addrman, &na)) {
    btc_pool_debug(pool, "Ignoring banned peer (%S).", &sa);
    btc_socket_close(socket);
    return;
  }

  btc_pool_info(pool, "Accepting inbound peer (%S).", &sa);

  peer = btc_peer_create(pool);

  if (!btc_peer_accept(peer, socket)) {
    const char *msg = btc_loop_strerror(pool->loop);

    btc_pool_debug(pool, "Connection failed: %s (%S).", msg, &sa);
    btc_peer_destroy(peer);

    return;
  }

  btc_peers_add(&pool->peers, peer);
}

static void
btc_pool_on_connect(btc_pool_t *pool, btc_peer_t *peer) {
  btc_pool_info(pool, "Connected to %N.", &peer->addr);

  if (peer->outbound)
    btc_addrman_mark_success(pool->addrman, &peer->addr);
}

static void
btc_pool_on_complete(btc_pool_t *pool, btc_peer_t *peer) {
  const btc_netaddr_t *addr;

  if (peer->outbound) {
    /* Advertise our address. */
    if ((pool->flags & BTC_POOL_LISTEN) && btc_chain_synced(pool->chain)) {
      addr = btc_addrman_get_local(pool->addrman, &peer->addr, pool->services);

      if (addr != NULL)
        btc_peer_send_addr_1(peer, addr);
    }

    /* Find some more peers. */
    btc_peer_send_getaddr(peer);
    peer->getting_addr = 1;
  }

  /* We want compact blocks! */
  if (pool->flags & BTC_POOL_BIP152)
    btc_peer_send_sendcmpct(peer, pool->block_mode);

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
btc_pool_resync(btc_pool_t *pool, int force) {
  btc_vector_t locator;
  btc_peer_t *peer;

  btc_vector_init(&locator);
  btc_chain_get_locator(pool->chain, &locator, NULL);

  for (peer = pool->peers.head; peer != NULL; peer = peer->next) {
    if (!peer->outbound)
      continue;

    if (!force && peer->syncing)
      continue;

    btc_pool_send_locator(pool, peer, &locator);
  }

  btc_vector_clear(&locator);
}

static int
btc_pool_resolve_block(btc_pool_t *pool,
                       btc_peer_t *peer,
                       const uint8_t *hash) {
  uint8_t *key = btc_hashtab_del(&peer->block_map, hash);

  if (key == NULL)
    return 0;

  CHECK(btc_hashset_del(&pool->block_map, hash) == key);

  btc_free(key);

  return 1;
}

static int
btc_pool_resolve_tx(btc_pool_t *pool,
                    btc_peer_t *peer,
                    const uint8_t *hash) {
  uint8_t *key = btc_hashtab_del(&peer->tx_map, hash);

  if (key == NULL)
    return 0;

  CHECK(btc_hashset_del(&pool->tx_map, hash) == key);

  btc_free(key);

  return 1;
}

static int
btc_pool_resolve_item(btc_pool_t *pool,
                      btc_peer_t *peer,
                      const btc_zinvitem_t *item) {
  switch (item->type) {
    case BTC_INV_TX:
    case BTC_INV_WITNESS_TX:
      return btc_pool_resolve_tx(pool, peer, item->hash);
    case BTC_INV_BLOCK:
    case BTC_INV_FILTERED_BLOCK:
    case BTC_INV_CMPCT_BLOCK:
    case BTC_INV_WITNESS_BLOCK:
    case BTC_INV_WITNESS_FILTERED_BLOCK:
      return btc_pool_resolve_block(pool, peer, item->hash);
    default:
      return 0;
  }
}

static void
btc_pool_remove_peer(btc_pool_t *pool, btc_peer_t *peer) {
  btc_mapiter_t it;

  btc_peers_remove(&pool->peers, peer);

  /* Remove block hashes. */
  btc_map_each(&peer->block_map, it)
    CHECK(btc_hashset_del(&pool->block_map, peer->block_map.keys[it]));

  /* Remove TXIDs. */
  btc_map_each(&peer->tx_map, it)
    CHECK(btc_hashset_del(&pool->tx_map, peer->tx_map.keys[it]));

  /* Remove compact block hashes. */
  btc_map_each(&peer->compact_map, it)
    CHECK(btc_hashset_del(&pool->compact_map, peer->compact_map.keys[it]));
}

static void
btc_pool_on_close(btc_pool_t *pool, btc_peer_t *peer) {
  size_t size = peer->block_map.size;
  int loader = peer->loader;

  btc_pool_remove_peer(pool, peer);

  if (loader) {
    btc_pool_info(pool, "Removed loader peer (%N).", &peer->addr);

    if (pool->checkpoints)
      btc_pool_reset_chain(pool);
  }

  btc_nonces_remove(&pool->nonces, peer->nonce);

  if (btc_chain_synced(pool->chain) && size > 0) {
    btc_pool_warn(pool, "Peer disconnected with requested blocks (%N).",
                       &peer->addr);
    btc_pool_warn(pool, "Resending sync...");
    btc_pool_resync(pool, 1);
  }

  btc_peer_destroy(peer);
}

static void
btc_pool_on_version(btc_pool_t *pool,
                    btc_peer_t *peer,
                    const btc_version_t *msg) {
  btc_pool_info(pool,
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
      btc_pool_warn(pool, "Adjusted time mismatch!");
      btc_pool_warn(pool, "Please make sure your system clock is correct!");
    }

    if (pool->timedata->length != length) {
      int64_t sample = msg->time - btc_now();

      btc_pool_debug(pool, "Added time data: total=%zu, sample=%T (%T minutes).",
                           pool->timedata->length, sample, sample / 60);
    }

    if (pool->timedata->offset != offset) {
      btc_pool_info(pool, "Time offset: %T (%T minutes).",
                          pool->timedata->offset,
                          pool->timedata->offset / 60);
    }
  }

  btc_nonces_remove(&pool->nonces, peer->nonce);

  if (!peer->outbound && btc_netaddr_is_routable(&msg->remote))
    btc_addrman_mark_local(pool->addrman, &msg->remote);
}

static void
btc_pool_on_verack(btc_pool_t *pool, btc_peer_t *peer) {
  (void)pool;
  (void)peer;
}

static void
btc_pool_on_ping(btc_pool_t *pool,
                 btc_peer_t *peer,
                 const btc_ping_t *ping) {
  (void)pool;
  (void)peer;
  (void)ping;
}

static void
btc_pool_on_pong(btc_pool_t *pool,
                 btc_peer_t *peer,
                 const btc_pong_t *pong) {
  (void)pool;
  (void)peer;
  (void)pong;
}

static void
btc_pool_on_getaddr(btc_pool_t *pool, btc_peer_t *peer) {
  btc_vector_t *snapshot;
  btc_addrs_t addrs;
  size_t i;

  if (peer->outbound) {
    btc_pool_debug(pool, "Ignoring getaddr from outbound node (%N).",
                         &peer->addr);
    return;
  }

  if (peer->sent_addr) {
    btc_pool_debug(pool, "Ignoring repeated getaddr (%N).",
                         &peer->addr);
    return;
  }

  peer->sent_addr = 1;

  btc_addrs_init(&addrs);

  snapshot = btc_addrman_getaddr(pool->addrman);

  for (i = 0; i < snapshot->length; i++) {
    const btc_netaddr_t *addr = snapshot->items[i];

    if (btc_filter_has_addr(&peer->addr_filter, addr))
      continue;

    btc_filter_add_addr(&peer->addr_filter, addr);

    btc_addrs_push(&addrs, (btc_netaddr_t *)addr);

    if (addrs.length == 1000)
      break;
  }

  if (addrs.length > 0) {
    btc_pool_debug(pool, "Sending %zu addrs to peer (%N)",
                         addrs.length, &peer->addr);

    btc_peer_send_addr(peer, &addrs);

    addrs.length = 0;
  }

  btc_vector_destroy(snapshot);
  btc_addrs_clear(&addrs);
}

static void
btc_pool_on_addr(btc_pool_t *pool,
                 btc_peer_t *peer,
                 const btc_addrs_t *addrs) {
  uint64_t services = pool->required_services;
  int64_t now = btc_timedata_now(pool->timedata);
  int64_t since = now - 10 * 60;
  btc_vector_t relay;
  size_t i;

  if (addrs->length > 1000) {
    btc_peer_increase_ban(peer, 20);
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

  btc_pool_info(pool, "Received %zu addrs (hosts=%zu, peers=%zu) (%N).",
                      addrs->length, btc_addrman_total(pool->addrman),
                      pool->peers.length, &peer->addr);

  if (relay.length > 0) {
    btc_vector_t peers;
    btc_peer_t *it;

    btc_pool_debug(pool, "Relaying %zu addrs to random peers.", relay.length);

    btc_vector_init(&peers);

    for (it = pool->peers.head; it != NULL; it = it->next) {
      if (it->state == BTC_PEER_CONNECTED)
        btc_vector_push(&peers, it);
    }

    if (peers.length > 0) {
      for (i = 0; i < relay.length; i++) {
        const btc_netaddr_t *addr = relay.items[i];
        btc_peer_t *peer1 = peers.items[btc_uniform(peers.length)];
        btc_peer_t *peer2 = peers.items[btc_uniform(peers.length)];

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
}

static void
btc_pool_resolve_orphan(btc_pool_t *pool,
                        btc_peer_t *peer,
                        const uint8_t *orphan) {
  const uint8_t *stop = btc_chain_get_orphan_root(pool->chain, orphan);
  btc_vector_t locator;

  CHECK(stop != NULL);

  btc_vector_init(&locator);
  btc_chain_get_locator(pool->chain, &locator, NULL);
  btc_peer_send_getblocks(peer, &locator, stop);
  btc_vector_clear(&locator);
}

static void
btc_pool_getblocks(btc_pool_t *pool,
                   btc_peer_t *peer,
                   const uint8_t *start,
                   const uint8_t *stop) {
  btc_vector_t locator;

  btc_vector_init(&locator);
  btc_chain_get_locator(pool->chain, &locator, start);
  btc_peer_send_getblocks(peer, &locator, stop);
  btc_vector_clear(&locator);
}

static void
btc_pool_request_blocks(btc_pool_t *pool,
                        btc_peer_t *peer,
                        const btc_vector_t *hashes) {
  btc_zinv_t inv;
  int64_t now;
  size_t i;

  if (peer->state != BTC_PEER_CONNECTED) {
    btc_pool_debug(pool, "Peer handshake not complete (getdata) (%N).",
                         &peer->addr);
    return;
  }

  now = btc_time_msec();

  btc_zinv_init(&inv);
  btc_zinv_grow(&inv, hashes->length);

  for (i = 0; i < hashes->length; i++) {
    const uint8_t *hash = hashes->items[i];
    uint8_t *key;

    if (btc_hashset_has(&pool->block_map, hash))
      continue;

    key = btc_hash_clone(hash);

    btc_hashset_put(&pool->block_map, key);
    btc_hashtab_put(&peer->block_map, key, now);

    if (btc_chain_synced(pool->chain))
      now += 100;

    btc_zinv_push(&inv, btc_peer_block_type(peer), hash);
  }

  if (inv.length == 0) {
    btc_zinv_clear(&inv);
    return;
  }

  if (peer->block_map.size >= BTC_NET_MAX_BLOCK_REQUEST) {
    btc_zinv_clear(&inv);
    btc_pool_warn(pool, "Peer advertised too many blocks (%N).",
                        &peer->addr);
    btc_peer_close(peer);
    return;
  }

  btc_pool_debug(pool, "Requesting %zu/%zu blocks from peer with getdata (%N).",
                       inv.length, (size_t)pool->block_map.size, &peer->addr);

  btc_peer_send_getdata(peer, &inv);

  btc_zinv_clear(&inv);
}

static void
btc_pool_on_blockinv(btc_pool_t *pool,
                     btc_peer_t *peer,
                     const btc_vector_t *hashes) {
  btc_vector_t out;
  size_t i;

  CHECK(hashes->length > 0);

  peer->gb_time = -1;

  /* Ignore for now if we're still syncing. */
  if (!btc_chain_synced(pool->chain) && !peer->loader)
    return;

  /* Request headers instead. */
  if (pool->checkpoints)
    return;

  btc_pool_debug(pool, "Received %zu block hashes from peer (%N).",
                       hashes->length, &peer->addr);

  btc_vector_init(&out);

  for (i = 0; i < hashes->length; i++) {
    const uint8_t *hash = hashes->items[i];

    /* Ignore invalid (maybe ban?). */
    if (btc_chain_has_invalid(pool->chain, hash))
      continue;

    /* Resolve orphan chain. */
    if (btc_chain_has_orphan(pool->chain, hash)) {
      btc_pool_debug(pool, "Received known orphan hash (%N).", &peer->addr);
      btc_pool_resolve_orphan(pool, peer, hash);
      continue;
    }

    /* Request the block if we don't have it. */
    if (!btc_chain_has_hash(pool->chain, hash)) {
      btc_vector_push(&out, hash);
      continue;
    }

    /* Normally we request the hashContinue.
       In the odd case where we already have
       it, we can do one of two things: either
       force re-downloading of the block to
       continue the sync, or do a getblocks
       from the last hash. */
    if (i == hashes->length - 1) {
      btc_pool_debug(pool, "Received existing hash (%N).", &peer->addr);
      btc_pool_getblocks(pool, peer, hash, NULL);
    }
  }

  btc_pool_request_blocks(pool, peer, &out);

  btc_vector_clear(&out);
}

static void
btc_pool_request_txs(btc_pool_t *pool,
                     btc_peer_t *peer,
                     const btc_vector_t *hashes) {
  btc_zinv_t inv;
  int64_t now;
  size_t i;

  if (peer->state != BTC_PEER_CONNECTED) {
    btc_pool_debug(pool, "Peer handshake not complete (getdata) (%N).",
                         &peer->addr);
    return;
  }

  now = btc_time_msec();

  btc_zinv_init(&inv);
  btc_zinv_grow(&inv, hashes->length);

  for (i = 0; i < hashes->length; i++) {
    const uint8_t *hash = hashes->items[i];
    uint8_t *key;

    if (btc_hashset_has(&pool->tx_map, hash))
      continue;

    key = btc_hash_clone(hash);

    btc_hashset_put(&pool->tx_map, key);
    btc_hashtab_put(&peer->tx_map, key, now);

    if (btc_chain_synced(pool->chain))
      now += 50;

    btc_zinv_push(&inv, btc_peer_tx_type(peer), hash);
  }

  if (inv.length == 0) {
    btc_zinv_clear(&inv);
    return;
  }

  if (peer->tx_map.size >= BTC_NET_MAX_TX_REQUEST) {
    btc_zinv_clear(&inv);
    btc_pool_warn(pool, "Peer advertised too many txs (%N).",
                        &peer->addr);
    btc_peer_close(peer);
    return;
  }

  btc_pool_debug(pool, "Requesting %zu/%zu txs from peer with getdata (%N).",
                       inv.length, (size_t)pool->tx_map.size, &peer->addr);

  btc_peer_send_getdata(peer, &inv);

  btc_zinv_clear(&inv);
}

static int
btc_pool_has_tx(btc_pool_t *pool, const uint8_t *hash) {
  /* Check the mempool. */
  if (btc_mempool_has(pool->mempool, hash))
    return 1;

  /* Check for orphans. */
  if (btc_mempool_has_orphan(pool->mempool, hash))
    return 1;

  /* If we recently rejected this item. Ignore. */
  if (btc_mempool_has_reject(pool->mempool, hash)) {
    btc_pool_spam(pool, "Saw known reject of %H.", hash);
    return 1;
  }

  return 0;
}

static void
btc_pool_on_txinv(btc_pool_t *pool,
                  btc_peer_t *peer,
                  const btc_vector_t *hashes) {
  btc_vector_t out;
  size_t i;

  CHECK(hashes->length > 0);

  if (!btc_chain_synced(pool->chain))
    return;

  if (pool->flags & BTC_POOL_BLOCKSONLY)
    return;

  btc_vector_init(&out);

  for (i = 0; i < hashes->length; i++) {
    const uint8_t *hash = hashes->items[i];

    if (btc_pool_has_tx(pool, hash))
      continue;

    btc_vector_push(&out, hash);
  }

  btc_pool_request_txs(pool, peer, &out);

  btc_vector_clear(&out);
}

static void
btc_pool_on_inv(btc_pool_t *pool,
                btc_peer_t *peer,
                const btc_zinv_t *inv) {
  int64_t unknown = -1;
  btc_vector_t blocks;
  btc_vector_t txs;
  size_t i;

  if (inv->length > BTC_NET_MAX_INV) {
    btc_peer_increase_ban(peer, 20);
    return;
  }

  btc_vector_init(&blocks);
  btc_vector_init(&txs);

  for (i = 0; i < inv->length; i++) {
    const btc_zinvitem_t *item = &inv->items[i];

    switch (item->type) {
      case BTC_INV_BLOCK:
        btc_vector_push(&blocks, item->hash);
        break;
      case BTC_INV_TX:
        btc_vector_push(&txs, item->hash);
        break;
      default:
        unknown = item->type;
        break;
    }

    btc_filter_add(&peer->inv_filter, item->hash, 32);
  }

  btc_pool_spam(pool,
    "Received inv message with %zu items: blocks=%zu txs=%zu (%N).",
    inv->length, blocks.length, txs.length, &peer->addr);

  if (unknown != -1) {
    btc_pool_debug(pool, "Peer sent an unknown inv type: %u (%N).",
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
btc_pool_on_getdata(btc_pool_t *pool,
                    btc_peer_t *peer,
                    const btc_zinv_t *msg) {
  size_t i;

  if (msg->length > BTC_NET_MAX_INV) {
    btc_pool_warn(pool, "Peer sent inv with >50k items (%n).",
                        &peer->addr);
    btc_peer_increase_ban(peer, 20);
    return;
  }

  for (i = 0; i < msg->length; i++)
    btc_peer_send_data(peer, btc_zinv_get(msg, i));

  btc_peer_flush_data(peer);

  if (peer->sending.length > BTC_NET_MAX_INV) {
    btc_peer_warn(peer, "Peer exceeded getdata queue (%N).", &peer->addr);
    btc_peer_close(peer);
    return;
  }
}

static void
btc_pool_on_notfound(btc_pool_t *pool,
                     btc_peer_t *peer,
                     const btc_zinv_t *msg) {
  size_t i;

  for (i = 0; i < msg->length; i++) {
    const btc_zinvitem_t *item = &msg->items[i];

    if (!btc_pool_resolve_item(pool, peer, item)) {
      btc_pool_warn(pool, "Peer sent notfound for unrequested item: %H (%N).",
                          item->hash, &peer->addr);
      btc_peer_close(peer);
      return;
    }
  }
}

static size_t
btc_pool_inv_size(btc_pool_t *pool,
                  const btc_entry_t *start,
                  const btc_entry_t *stop,
                  size_t max) {
  size_t length;

  if (start == NULL)
    return 0;

  if (stop == NULL || stop->height < start->height)
    stop = btc_chain_tip(pool->chain);

  length = stop->height - start->height + 1;

  if (length > max)
    length = max;

  return length;
}

static void
btc_pool_on_getblocks(btc_pool_t *pool,
                      btc_peer_t *peer,
                      const btc_getblocks_t *msg) {
  const btc_entry_t *entry, *stop;
  btc_zinv_t blocks;

  if (!btc_chain_synced(pool->chain))
    return;

  if (btc_chain_pruned(pool->chain))
    return;

  entry = btc_chain_find_locator(pool->chain, &msg->locator);

  if (entry != NULL)
    entry = entry->next;

  stop = btc_chain_by_hash(pool->chain, msg->stop);

  btc_zinv_init(&blocks);
  btc_zinv_grow(&blocks, btc_pool_inv_size(pool, entry, stop, 500));

  while (entry != NULL) {
    if (entry == stop)
      break;

    btc_zinv_push(&blocks, BTC_INV_BLOCK, entry->hash);

    if (blocks.length == 500) {
      btc_hash_copy(peer->hash_continue, entry->hash);
      break;
    }

    entry = entry->next;
  }

  if (blocks.length > 0)
    btc_peer_send_inv(peer, &blocks);

  btc_zinv_clear(&blocks);
}

static void
btc_pool_on_getheaders(btc_pool_t *pool,
                       btc_peer_t *peer,
                       const btc_getblocks_t *msg) {
  const btc_entry_t *entry, *stop;
  btc_headers_t blocks;

  if (!btc_chain_synced(pool->chain))
    return;

  if (btc_chain_pruned(pool->chain))
    return;

  if (msg->locator.length > 0) {
    entry = btc_chain_find_locator(pool->chain, &msg->locator);

    if (entry != NULL)
      entry = entry->next;

    stop = btc_chain_by_hash(pool->chain, msg->stop);
  } else {
    entry = btc_chain_by_hash(pool->chain, msg->stop);
    stop = entry;
  }

  btc_headers_init(&blocks);
  btc_headers_grow(&blocks, btc_pool_inv_size(pool, entry, stop, 2000));

  while (entry != NULL) {
    btc_headers_push(&blocks, (btc_header_t *)&entry->header);

    btc_filter_add(&peer->inv_filter, entry->hash, 32);

    if (entry == stop)
      break;

    if (blocks.length == 2000)
      break;

    entry = entry->next;
  }

  if (blocks.length > 0) {
    btc_peer_send_headers(peer, &blocks);
    blocks.length = 0;
  }

  btc_headers_clear(&blocks);
}

static void
btc_pool_resolve_headers(btc_pool_t *pool, btc_peer_t *peer) {
  btc_hdrnode_t *node;
  btc_vector_t items;

  btc_vector_init(&items);

  for (node = pool->header_next; node != NULL; node = node->next) {
    pool->header_next = node->next;

    btc_vector_push(&items, node->hash);

    if (items.length == BTC_NET_MAX_INV)
      break;
  }

  btc_pool_request_blocks(pool, peer, &items);
  btc_vector_clear(&items);
}

static void
btc_pool_shift_header(btc_pool_t *pool) {
  btc_hdrnode_t *node = pool->header_head;

  pool->header_head = node->next;

  if (node == pool->header_next)
    pool->header_next = NULL;

  btc_hdrnode_destroy(node);

  if (pool->header_head == NULL) {
    pool->header_tail = NULL;
    pool->header_next = NULL;
  }
}

static void
btc_pool_resolve_chain(btc_pool_t *pool,
                       btc_peer_t *peer,
                       const uint8_t *hash) {
  btc_hdrnode_t *node;

  if (!pool->checkpoints)
    return;

  if (!peer->loader)
    return;

  if (peer->state != BTC_PEER_CONNECTED)
    return;

  node = pool->header_head;

  CHECK(node != NULL);

  if (!btc_hash_equal(hash, node->hash)) {
    btc_pool_warn(pool, "Header hash mismatch %H != %H (%N).",
                        hash, node->hash, &peer->addr);

    btc_peer_close(peer);

    return;
  }

  if (node->height < pool->network->last_checkpoint) {
    if (node->height == pool->header_tip->height) {
      btc_pool_info(pool, "Received checkpoint %H (%d).",
                          node->hash, node->height);

      pool->header_tip = btc_pool_next_tip(pool, node->height);

      btc_peer_send_getheaders_1(peer, hash, pool->header_tip->hash);

      return;
    }

    btc_pool_resolve_headers(pool, peer);
    btc_pool_shift_header(pool);

    return;
  }

  btc_pool_info(pool, "Switching to getblocks (%N).",
                      &peer->addr);

  btc_pool_clear_chain(pool);

  btc_pool_getblocks(pool, peer, hash, NULL);
}

static void
btc_pool_on_headers(btc_pool_t *pool,
                    btc_peer_t *peer,
                    const btc_headers_t *msg) {
  btc_hdrnode_t *node = NULL;
  int checkpoint = 0;
  size_t i;

  peer->gh_time = -1;

  if (!pool->checkpoints)
    return;

  if (!peer->loader)
    return;

  if (msg->length == 0)
    return;

  if (msg->length > 2000) {
    btc_peer_increase_ban(peer, 20);
    return;
  }

  CHECK(pool->header_head != NULL);

  for (i = 0; i < msg->length; i++) {
    const btc_header_t *hdr = msg->items[i];
    btc_hdrnode_t *last = pool->header_tail;
    int32_t height = last->height + 1;
    uint8_t hash[32];

    if (!btc_header_verify(hdr)) {
      btc_pool_warn(pool, "Peer sent an invalid header (%N).",
                          &peer->addr);
      btc_peer_increase_ban(peer, 100);
      return;
    }

    if (!btc_hash_equal(hdr->prev_block, last->hash)) {
      btc_pool_warn(pool, "Peer sent a bad header chain (%N).",
                          &peer->addr);
      btc_peer_close(peer);
      return;
    }

    btc_header_hash(hash, hdr);

    if (height == pool->header_tip->height) {
      if (!btc_hash_equal(hash, pool->header_tip->hash)) {
        btc_pool_warn(pool, "Peer sent an invalid checkpoint (%N).",
                            &peer->addr);
        btc_peer_close(peer);
        return;
      }
      checkpoint = 1;
    }

    node = btc_hdrnode_create(hash, height);

    if (pool->header_next == NULL)
      pool->header_next = node;

    if (pool->header_head == NULL)
      pool->header_head = node;

    if (pool->header_tail != NULL)
      pool->header_tail->next = node;

    pool->header_tail = node;
  }

  btc_pool_debug(pool, "Received %zu headers from peer (%N).",
                       msg->length, &peer->addr);

  /* If we received a valid header
     chain, consider this a "block". */
  peer->block_time = btc_time_msec();

  /* Request the blocks we just added. */
  if (checkpoint) {
    btc_pool_resolve_headers(pool, peer);
    btc_pool_shift_header(pool);
    return;
  }

  /* Request more headers. */
  btc_peer_send_getheaders_1(peer, node->hash, pool->header_tip->hash);
}

static void
btc_pool_on_sendheaders(btc_pool_t *pool, btc_peer_t *peer) {
  (void)pool;
  (void)peer;
}

void
btc_pool_announce_block(btc_pool_t *pool,
                        const btc_block_t *block,
                        const uint8_t *hash) {
  btc_peer_t *peer;

  for (peer = pool->peers.head; peer != NULL; peer = peer->next) {
    if (peer->state != BTC_PEER_CONNECTED)
      continue;

    btc_peer_announce_block(peer, block, hash);
  }
}

void
btc_pool_announce_tx(btc_pool_t *pool, const btc_mpentry_t *entry) {
  btc_peer_t *peer;

  for (peer = pool->peers.head; peer != NULL; peer = peer->next) {
    if (peer->state != BTC_PEER_CONNECTED)
      continue;

    btc_peer_announce_tx(peer, entry);
  }
}

void
btc_pool_handle_badorphan(btc_pool_t *pool,
                          const char *msg,
                          const btc_verify_error_t *err,
                          unsigned int id) {
  btc_peer_t *peer = btc_peers_find(&pool->peers, id);

  if (peer == NULL) {
    btc_pool_warn(pool, "Could not find offending peer for orphan: %H (%u).",
                        err->hash, id);
    return;
  }

  btc_pool_debug(pool, "Punishing peer for sending a bad orphan (%N).",
                       &peer->addr);

  /* Punish the original peer who sent this. */
  btc_peer_reject(peer, msg, err);
}

static void
btc_pool_add_block(btc_pool_t *pool,
                   btc_peer_t *peer,
                   const btc_block_t *block,
                   unsigned int flags) {
  uint8_t hash[32];
  int32_t height;

  btc_header_hash(hash, &block->header);

  if (!btc_pool_resolve_block(pool, peer, hash)) {
    btc_pool_warn(pool, "Received unrequested block: %H (%N).",
                        hash, &peer->addr);
    btc_peer_close(peer);
    return;
  }

  peer->block_time = btc_time_msec();
  peer->last_ping = peer->block_time;

  if (!btc_chain_add(pool->chain, block, flags, peer->id)) {
    btc_peer_reject(peer, "block", btc_chain_error(pool->chain));
    return;
  }

  /* Block was orphaned. */
  if (btc_chain_has_orphan(pool->chain, hash)) {
    if (pool->checkpoints) {
      btc_pool_warn(pool, "Peer sent orphan block with getheaders (%N).",
                          &peer->addr);
      return;
    }

    btc_pool_debug(pool, "Peer sent an orphan block. Resolving.");
    btc_pool_resolve_orphan(pool, peer, hash);

    return;
  }

  if (!pool->synced && btc_chain_synced(pool->chain)) {
    pool->synced = 1;
    btc_pool_resync(pool, 0);
  }

  height = btc_chain_height(pool->chain);

  if (height % 20 == 0) {
    btc_pool_debug(pool, "Status:"
                         " time=%D height=%d progress=%.2f%%"
                         " orphans=%zu active=%zu"
                         " target=%#.8x peers=%zu",
      block->header.time,
      height,
      btc_chain_progress(pool->chain) * 100.0,
      btc_chain_orphans(pool->chain),
      (size_t)pool->block_map.size,
      block->header.bits,
      pool->peers.length);
  }

  if (height % 2000 == 0) {
    btc_pool_info(pool, "Received 2000 more blocks (height=%d, hash=%H).",
                        height, hash);
  }

  btc_pool_resolve_chain(pool, peer, hash);
}

static void
btc_pool_on_block(btc_pool_t *pool,
                  btc_peer_t *peer,
                  const btc_block_t *block) {
  btc_pool_add_block(pool, peer, block, BTC_BLOCK_DEFAULT_FLAGS);
}

static void
btc_pool_on_tx(btc_pool_t *pool, btc_peer_t *peer, const btc_tx_t *tx) {
  if (!btc_pool_resolve_tx(pool, peer, tx->hash)) {
    btc_pool_warn(pool, "Peer sent unrequested tx: %H (%N).",
                        tx->hash, &peer->addr);
    btc_peer_close(peer);
    return;
  }

  if (!btc_mempool_add(pool->mempool, tx, peer->id)) {
    btc_peer_reject(peer, "tx", btc_mempool_error(pool->mempool));
    return;
  }

  if (btc_mempool_has_orphan(pool->mempool, tx->hash)) {
    btc_vector_t *missing = btc_mempool_missing(pool->mempool, tx);

    if (missing->length > 0) {
      btc_pool_debug(pool, "Requesting %zu missing transactions (%N).",
                           missing->length, &peer->addr);

      btc_pool_request_txs(pool, peer, missing);
    }

    btc_vector_destroy(missing);

    return;
  }
}

static void
btc_pool_on_reject(btc_pool_t *pool,
                   btc_peer_t *peer,
                   const btc_reject_t *msg) {
  btc_pool_debug(pool, "Received reject (%N): msg=%s code=%s reason=%s hash=%H.",
                       &peer->addr,
                       msg->message,
                       btc_reject_code(msg->code),
                       msg->reason,
                       msg->hash);
}

static void
btc_pool_on_mempool(btc_pool_t *pool, btc_peer_t *peer) {
  const btc_hashmap_t *map = btc_mempool_map(pool->mempool);
  btc_zinv_t items;
  btc_mapiter_t it;

  if (!btc_chain_synced(pool->chain))
    return;

  if (!(pool->flags & BTC_POOL_BIP37)) {
    btc_pool_debug(pool, "Peer requested mempool without bip37 enabled (%N).",
                         &peer->addr);
    btc_peer_close(peer);
    return;
  }

  btc_pool_debug(pool, "Sending mempool snapshot (%N).", &peer->addr);

  btc_zinv_init(&items);
  btc_zinv_grow(&items, 1000);

  btc_map_each(map, it) {
    const btc_mpentry_t *entry = map->vals[it];

    btc_zinv_push(&items, BTC_INV_TX, entry->hash);

    if (items.length == 1000) {
      btc_peer_send_inv(peer, &items);
      btc_zinv_reset(&items);
    }
  }

  if (items.length > 0)
    btc_peer_send_inv(peer, &items);

  btc_zinv_clear(&items);
}

static void
btc_pool_on_filterload(btc_pool_t *pool,
                       btc_peer_t *peer,
                       const btc_bloom_t *filter) {
  (void)pool;
  (void)peer;
  (void)filter;
}

static void
btc_pool_on_filteradd(btc_pool_t *pool,
                      btc_peer_t *peer,
                      const btc_filteradd_t *msg) {
  (void)pool;
  (void)peer;
  (void)msg;
}

static void
btc_pool_on_filterclear(btc_pool_t *pool, btc_peer_t *peer) {
  (void)pool;
  (void)peer;
}

static void
btc_pool_on_merkleblock(btc_pool_t *pool,
                        btc_peer_t *peer,
                        const btc_merkleblock_t *msg) {
  (void)msg;

  btc_pool_warn(pool, "Peer sent unsolicited merkleblock (%N).",
                      &peer->addr);

  btc_peer_increase_ban(peer, 100);
}

static void
btc_pool_on_feefilter(btc_pool_t *pool,
                      btc_peer_t *peer,
                      const btc_feefilter_t *msg) {
  (void)pool;
  (void)peer;
  (void)msg;
}

static void
btc_pool_on_sendcmpct(btc_pool_t *pool,
                      btc_peer_t *peer,
                      const btc_sendcmpct_t *msg) {
  (void)pool;
  (void)peer;
  (void)msg;
}

static void
btc_pool_on_cmpctblock(btc_pool_t *pool,
                       btc_peer_t *peer,
                       btc_cmpct_t *block) {
  const btc_hashmap_t *map = btc_mempool_map(pool->mempool);
  int rc;

  if (!(pool->flags & BTC_POOL_BIP152)) {
    btc_pool_debug(pool, "Peer sent unsolicited cmpctblock (%N).",
                         &peer->addr);
    btc_peer_close(peer);
    return;
  }

  if (!btc_peer_has_compact_support(peer) || !btc_peer_has_compact(peer)) {
    btc_pool_debug(pool, "Peer sent unsolicited cmpctblock (%N).",
                         &peer->addr);
    btc_peer_close(peer);
    return;
  }

  if (btc_hashmap_has(&peer->compact_map, block->hash)) {
    btc_pool_debug(pool, "Peer sent us a duplicate compact block (%N).",
                         &peer->addr);
    return;
  }

  if (btc_hashset_has(&pool->compact_map, block->hash)) {
    btc_pool_debug(pool, "Already waiting for compact block %H (%N).",
                         block->hash, &peer->addr);
    return;
  }

  if (!btc_hashtab_has(&peer->block_map, block->hash)) {
    uint8_t *hash;

    if (pool->block_mode != 1) {
      btc_pool_debug(pool, "Peer sent us an unrequested compact block (%N).",
                           &peer->addr);
      btc_peer_close(peer);
      return;
    }

    btc_filter_add(&peer->inv_filter, block->hash, 32);

    CHECK(!btc_hashset_has(&pool->block_map, block->hash));

    hash = btc_hash_clone(block->hash);

    btc_hashset_put(&pool->block_map, hash);
    btc_hashtab_put(&peer->block_map, hash, btc_time_msec());
  }

  if (!btc_header_verify(&block->header)) {
    btc_pool_info(pool, "Peer sent an invalid compact block (%N).",
                        &peer->addr);
    btc_peer_increase_ban(peer, 100);
    return;
  }

  rc = btc_cmpct_setup(block);

  if (rc == -1) {
    btc_pool_debug(pool, "Peer sent an invalid compact block (%N).",
                         &peer->addr);
    btc_peer_increase_ban(peer, 100);
    return;
  }

  if (rc == 0) {
    btc_pool_warn(pool, "Siphash collision for %H. Requesting full block (%N).",
                        block->hash, &peer->addr);
    btc_peer_get_full_block(peer, block->hash);
    btc_peer_increase_ban(peer, 10);
    return;
  }

  if (btc_cmpct_fill_mempool(block, map, peer->compact_witness)) {
    btc_block_t *blk = btc_block_create();

    btc_pool_debug(pool, "Received full compact block %H (%N).",
                         block->hash, &peer->addr);

    btc_cmpct_finalize(blk, block);
    btc_pool_add_block(pool, peer, blk, BTC_BLOCK_VERIFY_BODY);
    btc_block_destroy(blk);

    return;
  }

  if (peer->compact_map.size >= 15) {
    btc_pool_warn(pool, "Compact block DoS attempt (%N).", &peer->addr);
    btc_peer_close(peer);
    return;
  }

  block->now = btc_time_msec();

  CHECK(btc_hashset_put(&pool->compact_map, block->hash));
  CHECK(btc_hashmap_put(&peer->compact_map, block->hash, btc_cmpct_ref(block)));

  btc_pool_debug(pool, "Received non-full compact block %H tx=%zu/%zu (%N).",
                       block->hash, block->count, block->avail.length,
                       &peer->addr);

  btc_peer_send_getblocktxn(peer, block);
}

static void
btc_pool_on_getblocktxn(btc_pool_t *pool,
                        btc_peer_t *peer,
                        const btc_getblocktxn_t *req) {
  const btc_entry_t *entry;
  btc_block_t *block;

  if (btc_chain_pruned(pool->chain))
    return;

  entry = btc_chain_by_hash(pool->chain, req->hash);

  if (entry == NULL) {
    btc_pool_debug(pool, "Peer sent getblocktxn for non-existent block (%N).",
                         &peer->addr);
    btc_peer_increase_ban(peer, 100);
    return;
  }

  if (entry->height < btc_chain_height(pool->chain) - 15) {
    btc_pool_debug(pool, "Peer sent a getblocktxn for a block > 15 deep (%N)",
                         &peer->addr);
    return;
  }

  block = btc_chain_get_block(pool->chain, entry);

  if (block == NULL) {
    btc_pool_error(pool, "Block data not found for %H (%N)",
                         entry->hash, &peer->addr);
    btc_peer_send_notfound_1(peer, BTC_INV_BLOCK, entry->hash);
    return;
  }

  btc_pool_debug(pool, "Sending blocktxn for %H to peer (%N).",
                       entry->hash, &peer->addr);

  btc_peer_send_blocktxn(peer, block, req);
  btc_block_destroy(block);
}

static void
btc_pool_on_blocktxn(btc_pool_t *pool,
                     btc_peer_t *peer,
                     const btc_blocktxn_t *res) {
  btc_cmpct_t *block = btc_hashmap_get(&peer->compact_map, res->hash);
  btc_block_t *blk;

  if (block == NULL) {
    btc_pool_debug(pool, "Peer sent unsolicited blocktxn (%N).",
                         &peer->addr);
    return;
  }

  CHECK(btc_hashset_del(&pool->compact_map, res->hash));
  CHECK(btc_hashmap_del(&peer->compact_map, res->hash));

  if (!btc_cmpct_fill_missing(block, res)) {
    btc_pool_warn(pool, "Peer sent non-full blocktxn for %H. "
                        "Requesting full block (%N).",
                        block->hash, &peer->addr);
    btc_peer_get_full_block(peer, res->hash);
    btc_peer_increase_ban(peer, 10);
    btc_cmpct_destroy(block);
    return;
  }

  btc_pool_debug(pool, "Filled compact block %H (%N).",
                       block->hash, &peer->addr);

  blk = btc_block_create();

  btc_cmpct_finalize(blk, block);
  btc_pool_add_block(pool, peer, blk, BTC_BLOCK_VERIFY_BODY);
  btc_block_destroy(blk);
  btc_cmpct_destroy(block);
}

static void
btc_pool_on_unknown(btc_pool_t *pool,
                    btc_peer_t *peer,
                    const btc_msg_t *msg) {
  btc_pool_debug(pool, "Unknown message: %s (%N).", msg->cmd, &peer->addr);
}

static void
btc_pool_on_msg(btc_pool_t *pool, btc_peer_t *peer, btc_msg_t *msg) {
  if (peer->state == BTC_PEER_DEAD)
    return;

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
      btc_pool_on_addr(pool, peer, (const btc_addrs_t *)msg->body);
      break;
    case BTC_MSG_INV:
      btc_pool_on_inv(pool, peer, (const btc_zinv_t *)msg->body);
      break;
    case BTC_MSG_GETDATA:
      btc_pool_on_getdata(pool, peer, (const btc_zinv_t *)msg->body);
      break;
    case BTC_MSG_NOTFOUND:
      btc_pool_on_notfound(pool, peer, (const btc_zinv_t *)msg->body);
      break;
    case BTC_MSG_GETBLOCKS:
      btc_pool_on_getblocks(pool, peer, (const btc_getblocks_t *)msg->body);
      break;
    case BTC_MSG_GETHEADERS:
      btc_pool_on_getheaders(pool, peer, (const btc_getblocks_t *)msg->body);
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
    case BTC_MSG_FILTERLOAD:
      btc_pool_on_filterload(pool, peer, (const btc_bloom_t *)msg->body);
      break;
    case BTC_MSG_FILTERADD:
      btc_pool_on_filteradd(pool, peer, (const btc_filteradd_t *)msg->body);
      break;
    case BTC_MSG_FILTERCLEAR:
      btc_pool_on_filterclear(pool, peer);
      break;
    case BTC_MSG_MERKLEBLOCK:
      btc_pool_on_merkleblock(pool, peer, (const btc_merkleblock_t *)msg->body);
      break;
    case BTC_MSG_FEEFILTER:
      btc_pool_on_feefilter(pool, peer, (const btc_feefilter_t *)msg->body);
      break;
    case BTC_MSG_SENDCMPCT:
      btc_pool_on_sendcmpct(pool, peer, (const btc_sendcmpct_t *)msg->body);
      break;
    case BTC_MSG_CMPCTBLOCK:
      btc_pool_on_cmpctblock(pool, peer, (btc_cmpct_t *)msg->body);
      break;
    case BTC_MSG_GETBLOCKTXN:
      btc_pool_on_getblocktxn(pool, peer, (const btc_getblocktxn_t *)msg->body);
      break;
    case BTC_MSG_BLOCKTXN:
      btc_pool_on_blocktxn(pool, peer, (const btc_blocktxn_t *)msg->body);
      break;
    case BTC_MSG_UNKNOWN:
      btc_pool_on_unknown(pool, peer, msg);
      break;
    default:
      break;
  }
}
