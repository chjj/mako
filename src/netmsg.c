/*!
 * netmsg.c - network messages for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mako/bip37.h>
#include <mako/bip152.h>
#include <mako/block.h>
#include <mako/bloom.h>
#include <mako/header.h>
#include <mako/netaddr.h>
#include <mako/netmsg.h>
#include <mako/net.h>
#include <mako/tx.h>
#include <mako/util.h>
#include <mako/vector.h>
#include "bio.h"
#include "impl.h"
#include "internal.h"

/*
 * Constants
 */

static const char *btc_cmds[] = {
  "addr",
  "block",
  "blocktxn",
  "cmpctblock",
  "feefilter",
  "filteradd",
  "filterclear",
  "filterload",
  "getaddr",
  "getblocks",
  "getblocktxn",
  "getdata",
  "getheaders",
  "headers",
  "inv",
  "mempool",
  "merkleblock",
  "notfound",
  "ping",
  "pong",
  "reject",
  "sendcmpct",
  "sendheaders",
  "tx",
  "verack",
  "version",
  /* Internal */
  "blocktxn", /* base */
  "block", /* base */
  "cmpctblock", /* base */
  "getdata", /* full */
  "inv", /* full */
  "notfound", /* full */
  "tx", /* base */
  "unknown"
};

/* Must be updated if internal types are added. */
#define BTC_INTERNAL_TYPES 8

static enum btc_msgtype
find_type(const char *cmd) {
  int end = lengthof(btc_cmds) - BTC_INTERNAL_TYPES - 1;
  int start = 0;
  int pos, cmp;

  while (start <= end) {
    pos = (start + end) >> 1;
    cmp = strcmp(btc_cmds[pos], cmd);

    if (cmp == 0)
      return (enum btc_msgtype)pos;

    if (cmp < 0)
      start = pos + 1;
    else
      end = pos - 1;
  }

  return BTC_MSG_UNKNOWN;
}

/*
 * Version
 */

DEFINE_SERIALIZABLE_OBJECT(btc_version, SCOPE_EXTERN)

void
btc_version_init(btc_version_t *msg) {
  msg->version = BTC_NET_PROTOCOL_VERSION;
  msg->services = BTC_NET_LOCAL_SERVICES;
  msg->time = btc_now();
  btc_netaddr_init(&msg->remote);
  btc_netaddr_init(&msg->local);
  msg->nonce = 0;
  memset(msg->agent, 0, sizeof(msg->agent));
  strcpy(msg->agent, BTC_NET_USER_AGENT);
  msg->height = 0;
  msg->relay = 1;
}

void
btc_version_clear(btc_version_t *msg) {
  btc_netaddr_clear(&msg->remote);
  btc_netaddr_clear(&msg->local);
}

void
btc_version_copy(btc_version_t *z, const btc_version_t *x) {
  z->version = x->version;
  z->services = x->services;
  z->time = x->time;
  btc_netaddr_copy(&z->remote, &x->remote);
  btc_netaddr_copy(&z->local, &x->local);
  z->nonce = x->nonce;
  strcpy(z->agent, x->agent);
  z->height = x->height;
  z->relay = x->relay;
}

size_t
btc_version_size(const btc_version_t *x) {
  size_t size = 0;
  size += 20;
  size += btc_smalladdr_size(&x->remote);
  size += btc_smalladdr_size(&x->local);
  size += 8;
  size += btc_string_size(x->agent);
  size += 5;
  return size;
}

uint8_t *
btc_version_write(uint8_t *zp, const btc_version_t *x) {
  zp = btc_int32_write(zp, x->version);
  zp = btc_uint64_write(zp, x->services);
  zp = btc_int64_write(zp, x->time);
  zp = btc_smalladdr_write(zp, &x->remote);
  zp = btc_smalladdr_write(zp, &x->local);
  zp = btc_uint64_write(zp, x->nonce);
  zp = btc_string_write(zp, x->agent);
  zp = btc_int32_write(zp, x->height);
  zp = btc_uint8_write(zp, x->relay);
  return zp;
}

int
btc_version_read(btc_version_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_int32_read(&z->version, xp, xn))
    return 0;

  if (!btc_uint64_read(&z->services, xp, xn))
    return 0;

  if (!btc_int64_read(&z->time, xp, xn))
    return 0;

  if (!btc_smalladdr_read(&z->remote, xp, xn))
    return 0;

  if (*xn > 0) {
    if (!btc_smalladdr_read(&z->local, xp, xn))
      return 0;

    if (!btc_uint64_read(&z->nonce, xp, xn))
      return 0;
  } else {
    btc_netaddr_init(&z->local);
    z->nonce = 0;
  }

  if (*xn > 0) {
    if (!btc_string_read(z->agent, sizeof(z->agent), xp, xn))
      return 0;
  } else {
    memset(z->agent, 0, sizeof(z->agent));
  }

  if (*xn > 0) {
    if (!btc_int32_read(&z->height, xp, xn))
      return 0;
  } else {
    z->height = 0;
  }

  if (*xn > 0) {
    if (!btc_uint8_read(&z->relay, xp, xn))
      return 0;
  } else {
    z->relay = 1;
  }

  if (z->version == 10300)
    z->version = 300;

  if (z->version < 0)
    return 0;

  if (z->time < 0)
    return 0;

  if (z->height < 0)
    z->height = 0;

  return 1;
}

/*
 * Ping
 */

DEFINE_SERIALIZABLE_OBJECT(btc_ping, SCOPE_EXTERN)

void
btc_ping_init(btc_ping_t *msg) {
  msg->nonce = 0;
}

void
btc_ping_clear(btc_ping_t *msg) {
  (void)msg;
}

void
btc_ping_copy(btc_ping_t *z, const btc_ping_t *x) {
  *z = *x;
}

size_t
btc_ping_size(const btc_ping_t *x) {
  return x->nonce != 0 ? 8 : 0;
}

uint8_t *
btc_ping_write(uint8_t *zp, const btc_ping_t *x) {
  if (x->nonce != 0)
    zp = btc_uint64_write(zp, x->nonce);
  return zp;
}

int
btc_ping_read(btc_ping_t *z, const uint8_t **xp, size_t *xn) {
  z->nonce = 0;

  if (*xn > 0) {
    if (!btc_uint64_read(&z->nonce, xp, xn))
      return 0;
  }

  return 1;
}

/*
 * Pong
 */

DEFINE_SERIALIZABLE_OBJECT(btc_pong, SCOPE_EXTERN)

void
btc_pong_init(btc_pong_t *msg) {
  msg->nonce = 0;
}

void
btc_pong_clear(btc_pong_t *msg) {
  (void)msg;
}

void
btc_pong_copy(btc_pong_t *z, const btc_pong_t *x) {
  *z = *x;
}

size_t
btc_pong_size(const btc_pong_t *x) {
  (void)x;
  return 8;
}

uint8_t *
btc_pong_write(uint8_t *zp, const btc_pong_t *x) {
  return btc_uint64_write(zp, x->nonce);
}

int
btc_pong_read(btc_pong_t *z, const uint8_t **xp, size_t *xn) {
  return btc_uint64_read(&z->nonce, xp, xn);
}

/*
 * Addr
 */

DEFINE_SERIALIZABLE_VECTOR(btc_addrs, btc_netaddr, SCOPE_EXTERN)

/*
 * Inv Item
 */

DEFINE_SERIALIZABLE_OBJECT(btc_invitem, SCOPE_EXTERN)

void
btc_invitem_init(btc_invitem_t *item) {
  item->type = 0;
  btc_hash_init(item->hash);
  item->next = NULL;
}

void
btc_invitem_clear(btc_invitem_t *item) {
  (void)item;
}

void
btc_invitem_copy(btc_invitem_t *z, const btc_invitem_t *x) {
  *z = *x;
}

void
btc_invitem_set(btc_invitem_t *z, uint32_t type, const uint8_t *hash) {
  z->type = type;
  btc_hash_copy(z->hash, hash);
}

static uint32_t
btc_invitem_type(const btc_invitem_t *x) {
  uint32_t type = x->type & ~((uint32_t)BTC_INV_WITNESS_FLAG);

  switch (type) {
    case BTC_INV_TX:
      return BTC_INV_TX;
    case BTC_INV_BLOCK:
    case BTC_INV_FILTERED_BLOCK:
    case BTC_INV_CMPCT_BLOCK:
      return BTC_INV_BLOCK;
  }

  return type;
}

uint32_t
btc_invitem_hash(const btc_invitem_t *x) {
  return btc_murmur3_sum(x->hash, 32, btc_invitem_type(x) ^ 0xfba4c795);
}

int
btc_invitem_equal(const btc_invitem_t *x, const btc_invitem_t *y) {
  if (btc_invitem_type(x) != btc_invitem_type(y))
    return 0;

  if (!btc_hash_equal(x->hash, y->hash))
    return 0;

  return 1;
}

size_t
btc_invitem_size(const btc_invitem_t *x) {
  (void)x;
  return 36;
}

uint8_t *
btc_invitem_write(uint8_t *zp, const btc_invitem_t *x) {
  zp = btc_uint32_write(zp, x->type);
  zp = btc_raw_write(zp, x->hash, 32);
  return zp;
}

int
btc_invitem_read(btc_invitem_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_uint32_read(&z->type, xp, xn))
    return 0;

  if (!btc_raw_read(z->hash, 32, xp, xn))
    return 0;

  return 1;
}

/*
 * Inv
 */

DEFINE_SERIALIZABLE_VECTOR(btc_inv, btc_invitem, SCOPE_EXTERN)

void
btc_inv_push_item(btc_inv_t *inv, uint32_t type, const uint8_t *hash) {
  btc_invitem_t *item = btc_invitem_create();
  btc_invitem_set(item, type, hash);
  btc_inv_push(inv, item);
}

/*
 * Inv (zero copy)
 */

DEFINE_OBJECT(btc_zinv, SCOPE_EXTERN)

void
btc_zinv_init(btc_zinv_t *z) {
  z->items = NULL;
  z->alloc = 0;
  z->length = 0;
}

void
btc_zinv_clear(btc_zinv_t *z) {
  if (z->alloc > 0)
    btc_free(z->items);

  z->items = NULL;
  z->alloc = 0;
  z->length = 0;
}

void
btc_zinv_copy(btc_zinv_t *z, const btc_zinv_t *x) {
  size_t i;

  btc_zinv_grow(z, x->length);

  for (i = 0; i < x->length; i++) {
    z->items[i].type = x->items[i].type;
    z->items[i].hash = x->items[i].hash;
  }

  z->length = x->length;
}

void
btc_zinv_reset(btc_zinv_t *z) {
  z->length = 0;
}

void
btc_zinv_grow(btc_zinv_t *z, size_t zn) {
  if (zn > z->alloc) {
    z->items =
      (btc_zinvitem_t *)btc_realloc(z->items, zn * sizeof(btc_zinvitem_t));
    z->alloc = zn;
  }
}

void
btc_zinv_push(btc_zinv_t *z, uint32_t type, const uint8_t *hash) {
  btc_zinvitem_t *item;

  if (z->length == z->alloc)
    btc_zinv_grow(z, (z->alloc * 3) / 2 + (z->alloc <= 1));

  item = &z->items[z->length++];
  item->type = type;
  item->hash = hash;
}

btc_invitem_t *
btc_zinv_get(const btc_zinv_t *z, size_t index) {
  btc_zinvitem_t *item = &z->items[index];
  btc_invitem_t *ret = btc_invitem_create();
  btc_invitem_set(ret, item->type, item->hash);
  return ret;
}

static size_t
btc_zinv_size(const btc_zinv_t *x) {
  return btc_size_size(x->length) + x->length * 36;
}

static uint8_t *
btc_zinv_write(uint8_t *zp, const btc_zinv_t *x) {
  const btc_zinvitem_t *item;
  size_t i;

  zp = btc_size_write(zp, x->length);

  for (i = 0; i < x->length; i++) {
    item = &x->items[i];

    zp = btc_uint32_write(zp, item->type);
    zp = btc_raw_write(zp, item->hash, 32);
  }

  return zp;
}

static int
btc_zinv_read(btc_zinv_t *z, const uint8_t **xp, size_t *xn) {
  btc_zinvitem_t *item;
  size_t i, length;

  if (!btc_size_read(&length, xp, xn))
    return 0;

  if (*xn < length * 36)
    return 0;

  btc_zinv_grow(z, length);

  /* The parser is currently holding all of `*xp`
     in memory until btc_parser_parse returns.
     Zero copy here makes us crazy fast. */
  for (i = 0; i < length; i++) {
    item = &z->items[i];

    item->type = btc_read32le(*xp);
    item->hash = *xp + 4;

    *xp += 36;
    *xn -= 36;
  }

  z->length = length;

  return 1;
}

/*
 * GetBlocks
 */

DEFINE_SERIALIZABLE_OBJECT(btc_getblocks, SCOPE_EXTERN)

void
btc_getblocks_init(btc_getblocks_t *msg) {
  msg->version = 0;
  btc_vector_init(&msg->locator);
  msg->stop = btc_hash_zero;
}

void
btc_getblocks_clear(btc_getblocks_t *msg) {
  btc_vector_clear(&msg->locator);
}

void
btc_getblocks_copy(btc_getblocks_t *z, const btc_getblocks_t *x) {
  z->version = x->version;
  btc_vector_copy(&z->locator, &x->locator);
  z->stop = x->stop;
}

size_t
btc_getblocks_size(const btc_getblocks_t *x) {
  size_t size = 0;
  size += 4;
  size += btc_size_size(x->locator.length);
  size += 32 * x->locator.length;
  size += 32;
  return size;
}

uint8_t *
btc_getblocks_write(uint8_t *zp, const btc_getblocks_t *x) {
  size_t i;

  zp = btc_uint32_write(zp, x->version);
  zp = btc_size_write(zp, x->locator.length);

  for (i = 0; i < x->locator.length; i++)
    zp = btc_raw_write(zp, (const uint8_t *)x->locator.items[i], 32);

  zp = btc_raw_write(zp, x->stop, 32);

  return zp;
}

int
btc_getblocks_read(btc_getblocks_t *z, const uint8_t **xp, size_t *xn) {
  size_t i, length;

  if (!btc_uint32_read(&z->version, xp, xn))
    return 0;

  if (!btc_size_read(&length, xp, xn))
    return 0;

  if (length > BTC_NET_MAX_INV)
    return 0;

  if (*xn < length * 32 + 32)
    return 0;

  btc_vector_resize(&z->locator, length);

  for (i = 0; i < length; i++) {
    z->locator.items[i] = (void *)*xp;

    *xp += 32;
    *xn -= 32;
  }

  if (!btc_zraw_read(&z->stop, 32, xp, xn))
    return 0;

  return 1;
}

/*
 * Hdr
 */

typedef btc_header_t btc_hdr_t;

static btc_header_t *
btc_hdr_create(void) {
  return btc_header_create();
}

static void
btc_hdr_destroy(btc_header_t *hdr) {
  btc_header_destroy(hdr);
}

static btc_header_t *
btc_hdr_clone(const btc_header_t *hdr) {
  return btc_header_clone(hdr);
}

static size_t
btc_hdr_size(const btc_header_t *x) {
  return btc_header_size(x) + btc_size_size(0);
}

static uint8_t *
btc_hdr_write(uint8_t *zp, const btc_header_t *x) {
  zp = btc_header_write(zp, x);
  zp = btc_size_write(zp, 0);
  return zp;
}

static int
btc_hdr_read(btc_header_t *z, const uint8_t **xp, size_t *xn) {
  size_t len;

  if (!btc_header_read(z, xp, xn))
    return 0;

  if (!btc_size_read(&len, xp, xn))
    return 0;

  return 1;
}

/*
 * Headers
 */

DEFINE_SERIALIZABLE_VECTOR(btc_headers, btc_hdr, SCOPE_EXTERN)

/*
 * Reject
 */

DEFINE_SERIALIZABLE_OBJECT(btc_reject, SCOPE_EXTERN)

void
btc_reject_init(btc_reject_t *msg) {
  memset(msg->message, 0, sizeof(msg->message));

  msg->code = BTC_REJECT_INVALID;

  memset(msg->reason, 0, sizeof(msg->reason));

  btc_hash_init(msg->hash);
}

void
btc_reject_clear(btc_reject_t *msg) {
  (void)msg;
}

void
btc_reject_copy(btc_reject_t *z, const btc_reject_t *x) {
  *z = *x;
}

size_t
btc_reject_size(const btc_reject_t *x) {
  size_t size = 0;

  size += btc_string_size(x->message);
  size += 1;
  size += btc_string_size(x->reason);

  if (!btc_hash_is_null(x->hash))
    size += 32;

  return size;
}

uint8_t *
btc_reject_write(uint8_t *zp, const btc_reject_t *x) {
  zp = btc_string_write(zp, x->message);
  zp = btc_uint8_write(zp, x->code);
  zp = btc_string_write(zp, x->reason);

  if (!btc_hash_is_null(x->hash))
    zp = btc_raw_write(zp, x->hash, 32);

  return zp;
}

int
btc_reject_read(btc_reject_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_string_read(z->message, sizeof(z->message), xp, xn))
    return 0;

  if (!btc_uint8_read(&z->code, xp, xn))
    return 0;

  if (!btc_string_read(z->reason, sizeof(z->reason), xp, xn))
    return 0;

  if (strcmp(z->message, "block") == 0 || strcmp(z->message, "tx") == 0) {
    if (!btc_raw_read(z->hash, 32, xp, xn))
      return 0;
  } else {
    btc_hash_init(z->hash);
  }

  return 1;
}

const char *
btc_reject_code(unsigned int code) {
  switch (code) {
    case BTC_REJECT_MALFORMED:
      return "malformed";
    case BTC_REJECT_INVALID:
      return "invalid";
    case BTC_REJECT_OBSOLETE:
      return "obsolete";
    case BTC_REJECT_DUPLICATE:
      return "duplicate";
    case BTC_REJECT_NONSTANDARD:
      return "nonstandard";
    case BTC_REJECT_DUST:
      return "dust";
    case BTC_REJECT_INSUFFICIENTFEE:
      return "insufficientfee";
    case BTC_REJECT_CHECKPOINT:
      return "checkpoint";
    case BTC_REJECT_INTERNAL:
      return "internal";
    case BTC_REJECT_HIGHFEE:
      return "highfee";
    case BTC_REJECT_ALREADYKNOWN:
      return "alreadyknown";
    case BTC_REJECT_CONFLICT:
      return "conflict";
  }
  return "invalid";
}

/*
 * FilterAdd
 */

DEFINE_SERIALIZABLE_OBJECT(btc_filteradd, SCOPE_EXTERN)

void
btc_filteradd_init(btc_filteradd_t *msg) {
  msg->data = NULL;
  msg->length = 0;
}

void
btc_filteradd_clear(btc_filteradd_t *msg) {
  msg->data = NULL;
  msg->length = 0;
}

void
btc_filteradd_copy(btc_filteradd_t *z, const btc_filteradd_t *x) {
  *z = *x;
}

size_t
btc_filteradd_size(const btc_filteradd_t *x) {
  return btc_size_size(x->length) + x->length;
}

uint8_t *
btc_filteradd_write(uint8_t *zp, const btc_filteradd_t *x) {
  zp = btc_size_write(zp, x->length);
  zp = btc_raw_write(zp, x->data, x->length);
  return zp;
}

int
btc_filteradd_read(btc_filteradd_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_size_read(&z->length, xp, xn))
    return 0;

  if (!btc_zraw_read(&z->data, z->length, xp, xn))
    return 0;

  return 1;
}

/*
 * FeeFilter
 */

DEFINE_SERIALIZABLE_OBJECT(btc_feefilter, SCOPE_EXTERN)

void
btc_feefilter_init(btc_feefilter_t *msg) {
  msg->rate = 0;
}

void
btc_feefilter_clear(btc_feefilter_t *msg) {
  msg->rate = 0;
}

void
btc_feefilter_copy(btc_feefilter_t *z, const btc_feefilter_t *x) {
  z->rate = x->rate;
}

size_t
btc_feefilter_size(const btc_feefilter_t *x) {
  (void)x;
  return 8;
}

uint8_t *
btc_feefilter_write(uint8_t *zp, const btc_feefilter_t *x) {
  return btc_int64_write(zp, x->rate);
}

int
btc_feefilter_read(btc_feefilter_t *z, const uint8_t **xp, size_t *xn) {
  return btc_int64_read(&z->rate, xp, xn);
}

/*
 * SendCmpct
 */

DEFINE_SERIALIZABLE_OBJECT(btc_sendcmpct, SCOPE_EXTERN)

void
btc_sendcmpct_init(btc_sendcmpct_t *msg) {
  msg->mode = 0;
  msg->version = 1;
}

void
btc_sendcmpct_clear(btc_sendcmpct_t *msg) {
  (void)msg;
}

void
btc_sendcmpct_copy(btc_sendcmpct_t *z, const btc_sendcmpct_t *x) {
  *z = *x;
}

size_t
btc_sendcmpct_size(const btc_sendcmpct_t *x) {
  (void)x;
  return 9;
}

uint8_t *
btc_sendcmpct_write(uint8_t *zp, const btc_sendcmpct_t *x) {
  zp = btc_uint8_write(zp, x->mode);
  zp = btc_uint64_write(zp, x->version);
  return zp;
}

int
btc_sendcmpct_read(btc_sendcmpct_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_uint8_read(&z->mode, xp, xn))
    return 0;

  if (!btc_uint64_read(&z->version, xp, xn))
    return 0;

  return 1;
}

/*
 * Unknown
 */

DEFINE_SERIALIZABLE_OBJECT(btc_unknown, SCOPE_EXTERN)

void
btc_unknown_init(btc_unknown_t *msg) {
  msg->data = NULL;
  msg->length = 0;
}

void
btc_unknown_clear(btc_unknown_t *msg) {
  msg->data = NULL;
  msg->length = 0;
}

void
btc_unknown_copy(btc_unknown_t *z, const btc_unknown_t *x) {
  z->data = x->data;
  z->length = x->length;
}

size_t
btc_unknown_size(const btc_unknown_t *x) {
  return x->length;
}

uint8_t *
btc_unknown_write(uint8_t *zp, const btc_unknown_t *x) {
  return btc_raw_write(zp, x->data, x->length);
}

int
btc_unknown_read(btc_unknown_t *z, const uint8_t **xp, size_t *xn) {
  z->data = *xp;
  z->length = *xn;

  *xp += *xn;
  *xn = 0;

  return 1;
}

/*
 * Message
 */

DEFINE_SERIALIZABLE_OBJECT(btc_msg, SCOPE_EXTERN)

void
btc_msg_init(btc_msg_t *msg) {
  msg->type = BTC_MSG_UNKNOWN;
  memset(msg->cmd, 0, sizeof(msg->cmd));
  msg->body = NULL;
}

void
btc_msg_clear(btc_msg_t *msg) {
  if (msg->body == NULL)
    return;

  switch (msg->type) {
    case BTC_MSG_VERSION:
      btc_version_destroy((btc_version_t *)msg->body);
      break;
    case BTC_MSG_VERACK:
      break;
    case BTC_MSG_PING:
      btc_ping_destroy((btc_ping_t *)msg->body);
      break;
    case BTC_MSG_PONG:
      btc_pong_destroy((btc_pong_t *)msg->body);
      break;
    case BTC_MSG_GETADDR:
      break;
    case BTC_MSG_ADDR:
      btc_addrs_destroy((btc_addrs_t *)msg->body);
      break;
    case BTC_MSG_INV:
    case BTC_MSG_GETDATA:
    case BTC_MSG_NOTFOUND:
      btc_zinv_destroy((btc_zinv_t *)msg->body);
      break;
    case BTC_MSG_INV_FULL:
    case BTC_MSG_GETDATA_FULL:
    case BTC_MSG_NOTFOUND_FULL:
      btc_inv_destroy((btc_inv_t *)msg->body);
      break;
    case BTC_MSG_GETBLOCKS:
    case BTC_MSG_GETHEADERS:
      btc_getblocks_destroy((btc_getblocks_t *)msg->body);
      break;
    case BTC_MSG_HEADERS:
      btc_headers_destroy((btc_headers_t *)msg->body);
      break;
    case BTC_MSG_SENDHEADERS:
      break;
    case BTC_MSG_BLOCK:
    case BTC_MSG_BLOCK_BASE:
      btc_block_destroy((btc_block_t *)msg->body);
      break;
    case BTC_MSG_TX:
    case BTC_MSG_TX_BASE:
      btc_tx_destroy((btc_tx_t *)msg->body);
      break;
    case BTC_MSG_REJECT:
      btc_reject_destroy((btc_reject_t *)msg->body);
      break;
    case BTC_MSG_MEMPOOL:
      break;
    case BTC_MSG_FILTERLOAD:
      btc_bloom_destroy((btc_bloom_t *)msg->body);
      break;
    case BTC_MSG_FILTERADD:
      btc_filteradd_destroy((btc_filteradd_t *)msg->body);
      break;
    case BTC_MSG_FILTERCLEAR:
      break;
    case BTC_MSG_MERKLEBLOCK:
      btc_merkleblock_destroy((btc_merkleblock_t *)msg->body);
      break;
    case BTC_MSG_FEEFILTER:
      btc_feefilter_destroy((btc_feefilter_t *)msg->body);
      break;
    case BTC_MSG_SENDCMPCT:
      btc_sendcmpct_destroy((btc_sendcmpct_t *)msg->body);
      break;
    case BTC_MSG_CMPCTBLOCK:
    case BTC_MSG_CMPCTBLOCK_BASE:
      btc_cmpct_destroy((btc_cmpct_t *)msg->body);
      break;
    case BTC_MSG_GETBLOCKTXN:
      btc_getblocktxn_destroy((btc_getblocktxn_t *)msg->body);
      break;
    case BTC_MSG_BLOCKTXN:
    case BTC_MSG_BLOCKTXN_BASE:
      btc_blocktxn_destroy((btc_blocktxn_t *)msg->body);
      break;
    case BTC_MSG_UNKNOWN:
      btc_unknown_destroy((btc_unknown_t *)msg->body);
      break;
    default:
      break;
  }

  msg->body = NULL;
}

void
btc_msg_copy(btc_msg_t *z, const btc_msg_t *x) {
  *z = *x;
}

void
btc_msg_set_type(btc_msg_t *msg, enum btc_msgtype type) {
  msg->type = type;
  strcpy(msg->cmd, btc_cmds[type]);
}

void
btc_msg_set_cmd(btc_msg_t *msg, const char *cmd) {
  enum btc_msgtype type = find_type(cmd);
  size_t len = strlen(cmd);

  CHECK(len + 1 <= sizeof(msg->cmd));

  msg->type = type;

  memcpy(msg->cmd, cmd, len + 1);
}

void
btc_msg_alloc(btc_msg_t *msg) {
  switch (msg->type) {
    case BTC_MSG_VERSION:
      msg->body = btc_version_create();
      break;
    case BTC_MSG_VERACK:
      msg->body = NULL;
      break;
    case BTC_MSG_PING:
      msg->body = btc_ping_create();
      break;
    case BTC_MSG_PONG:
      msg->body = btc_pong_create();
      break;
    case BTC_MSG_GETADDR:
      msg->body = NULL;
      break;
    case BTC_MSG_ADDR:
      msg->body = btc_addrs_create();
      break;
    case BTC_MSG_INV:
    case BTC_MSG_GETDATA:
    case BTC_MSG_NOTFOUND:
      msg->body = btc_zinv_create();
      break;
    case BTC_MSG_INV_FULL:
    case BTC_MSG_GETDATA_FULL:
    case BTC_MSG_NOTFOUND_FULL:
      msg->body = btc_inv_create();
      break;
    case BTC_MSG_GETBLOCKS:
    case BTC_MSG_GETHEADERS:
      msg->body = btc_getblocks_create();
      break;
    case BTC_MSG_HEADERS:
      msg->body = btc_headers_create();
      break;
    case BTC_MSG_SENDHEADERS:
      msg->body = NULL;
      break;
    case BTC_MSG_BLOCK:
    case BTC_MSG_BLOCK_BASE:
      msg->body = btc_block_create();
      break;
    case BTC_MSG_TX:
    case BTC_MSG_TX_BASE:
      msg->body = btc_tx_create();
      break;
    case BTC_MSG_REJECT:
      msg->body = btc_reject_create();
      break;
    case BTC_MSG_MEMPOOL:
      msg->body = NULL;
      break;
    case BTC_MSG_FILTERLOAD:
      msg->body = btc_bloom_create();
      break;
    case BTC_MSG_FILTERADD:
      msg->body = btc_filteradd_create();
      break;
    case BTC_MSG_FILTERCLEAR:
      msg->body = NULL;
      break;
    case BTC_MSG_MERKLEBLOCK:
      msg->body = btc_merkleblock_create();
      break;
    case BTC_MSG_FEEFILTER:
      msg->body = btc_feefilter_create();
      break;
    case BTC_MSG_SENDCMPCT:
      msg->body = btc_sendcmpct_create();
      break;
    case BTC_MSG_CMPCTBLOCK:
    case BTC_MSG_CMPCTBLOCK_BASE:
      msg->body = btc_cmpct_create();
      break;
    case BTC_MSG_GETBLOCKTXN:
      msg->body = btc_getblocktxn_create();
      break;
    case BTC_MSG_BLOCKTXN:
    case BTC_MSG_BLOCKTXN_BASE:
      msg->body = btc_blocktxn_create();
      break;
    case BTC_MSG_UNKNOWN:
      msg->body = btc_unknown_create();
      break;
    default:
      msg->body = NULL;
      break;
  }
}

size_t
btc_msg_size(const btc_msg_t *x) {
  switch (x->type) {
    case BTC_MSG_VERSION:
      return btc_version_size((const btc_version_t *)x->body);
    case BTC_MSG_VERACK:
      return 0;
    case BTC_MSG_PING:
      return btc_ping_size((const btc_ping_t *)x->body);
    case BTC_MSG_PONG:
      return btc_pong_size((const btc_pong_t *)x->body);
    case BTC_MSG_GETADDR:
      return 0;
    case BTC_MSG_ADDR:
      return btc_addrs_size((const btc_addrs_t *)x->body);
    case BTC_MSG_INV:
    case BTC_MSG_GETDATA:
    case BTC_MSG_NOTFOUND:
      return btc_zinv_size((const btc_zinv_t *)x->body);
    case BTC_MSG_INV_FULL:
    case BTC_MSG_GETDATA_FULL:
    case BTC_MSG_NOTFOUND_FULL:
      return btc_inv_size((const btc_inv_t *)x->body);
    case BTC_MSG_GETBLOCKS:
    case BTC_MSG_GETHEADERS:
      return btc_getblocks_size((const btc_getblocks_t *)x->body);
    case BTC_MSG_HEADERS:
      return btc_headers_size((const btc_headers_t *)x->body);
    case BTC_MSG_SENDHEADERS:
      return 0;
    case BTC_MSG_BLOCK:
      return btc_block_size((const btc_block_t *)x->body);
    case BTC_MSG_BLOCK_BASE:
      return btc_block_base_size((const btc_block_t *)x->body);
    case BTC_MSG_TX:
      return btc_tx_size((const btc_tx_t *)x->body);
    case BTC_MSG_TX_BASE:
      return btc_tx_base_size((const btc_tx_t *)x->body);
    case BTC_MSG_REJECT:
      return btc_reject_size((const btc_reject_t *)x->body);
    case BTC_MSG_MEMPOOL:
      return 0;
    case BTC_MSG_FILTERLOAD:
      return btc_bloom_size((const btc_bloom_t *)x->body);
    case BTC_MSG_FILTERADD:
      return btc_filteradd_size((const btc_filteradd_t *)x->body);
    case BTC_MSG_FILTERCLEAR:
      return 0;
    case BTC_MSG_MERKLEBLOCK:
      return btc_merkleblock_size((const btc_merkleblock_t *)x->body);
    case BTC_MSG_FEEFILTER:
      return btc_feefilter_size((const btc_feefilter_t *)x->body);
    case BTC_MSG_SENDCMPCT:
      return btc_sendcmpct_size((const btc_sendcmpct_t *)x->body);
    case BTC_MSG_CMPCTBLOCK:
      return btc_cmpct_size((const btc_cmpct_t *)x->body);
    case BTC_MSG_CMPCTBLOCK_BASE:
      return btc_cmpct_base_size((const btc_cmpct_t *)x->body);
    case BTC_MSG_GETBLOCKTXN:
      return btc_getblocktxn_size((const btc_getblocktxn_t *)x->body);
    case BTC_MSG_BLOCKTXN:
      return btc_blocktxn_size((const btc_blocktxn_t *)x->body);
    case BTC_MSG_BLOCKTXN_BASE:
      return btc_blocktxn_base_size((const btc_blocktxn_t *)x->body);
    case BTC_MSG_UNKNOWN:
      return btc_unknown_size((const btc_unknown_t *)x->body);
    default:
      return 0;
  }
}

uint8_t *
btc_msg_write(uint8_t *zp, const btc_msg_t *x) {
  switch (x->type) {
    case BTC_MSG_VERSION:
      return btc_version_write(zp, (const btc_version_t *)x->body);
    case BTC_MSG_VERACK:
      return zp;
    case BTC_MSG_PING:
      return btc_ping_write(zp, (const btc_ping_t *)x->body);
    case BTC_MSG_PONG:
      return btc_pong_write(zp, (const btc_pong_t *)x->body);
    case BTC_MSG_GETADDR:
      return zp;
    case BTC_MSG_ADDR:
      return btc_addrs_write(zp, (const btc_addrs_t *)x->body);
    case BTC_MSG_INV:
    case BTC_MSG_GETDATA:
    case BTC_MSG_NOTFOUND:
      return btc_zinv_write(zp, (const btc_zinv_t *)x->body);
    case BTC_MSG_INV_FULL:
    case BTC_MSG_GETDATA_FULL:
    case BTC_MSG_NOTFOUND_FULL:
      return btc_inv_write(zp, (const btc_inv_t *)x->body);
    case BTC_MSG_GETBLOCKS:
    case BTC_MSG_GETHEADERS:
      return btc_getblocks_write(zp, (const btc_getblocks_t *)x->body);
    case BTC_MSG_HEADERS:
      return btc_headers_write(zp, (const btc_headers_t *)x->body);
    case BTC_MSG_SENDHEADERS:
      return zp;
    case BTC_MSG_BLOCK:
      return btc_block_write(zp, (const btc_block_t *)x->body);
    case BTC_MSG_BLOCK_BASE:
      return btc_block_base_write(zp, (const btc_block_t *)x->body);
    case BTC_MSG_TX:
      return btc_tx_write(zp, (const btc_tx_t *)x->body);
    case BTC_MSG_TX_BASE:
      return btc_tx_base_write(zp, (const btc_tx_t *)x->body);
    case BTC_MSG_REJECT:
      return btc_reject_write(zp, (const btc_reject_t *)x->body);
    case BTC_MSG_MEMPOOL:
      return zp;
    case BTC_MSG_FILTERLOAD:
      return btc_bloom_write(zp, (const btc_bloom_t *)x->body);
    case BTC_MSG_FILTERADD:
      return btc_filteradd_write(zp, (const btc_filteradd_t *)x->body);
    case BTC_MSG_FILTERCLEAR:
      return zp;
    case BTC_MSG_MERKLEBLOCK:
      return btc_merkleblock_write(zp, (const btc_merkleblock_t *)x->body);
    case BTC_MSG_FEEFILTER:
      return btc_feefilter_write(zp, (const btc_feefilter_t *)x->body);
    case BTC_MSG_SENDCMPCT:
      return btc_sendcmpct_write(zp, (const btc_sendcmpct_t *)x->body);
    case BTC_MSG_CMPCTBLOCK:
      return btc_cmpct_write(zp, (const btc_cmpct_t *)x->body);
    case BTC_MSG_CMPCTBLOCK_BASE:
      return btc_cmpct_base_write(zp, (const btc_cmpct_t *)x->body);
    case BTC_MSG_GETBLOCKTXN:
      return btc_getblocktxn_write(zp, (const btc_getblocktxn_t *)x->body);
    case BTC_MSG_BLOCKTXN:
      return btc_blocktxn_write(zp, (const btc_blocktxn_t *)x->body);
    case BTC_MSG_BLOCKTXN_BASE:
      return btc_blocktxn_base_write(zp, (const btc_blocktxn_t *)x->body);
    case BTC_MSG_UNKNOWN:
      return btc_unknown_write(zp, (const btc_unknown_t *)x->body);
    default:
      return zp;
  }
}

int
btc_msg_read(btc_msg_t *z, const uint8_t **xp, size_t *xn) {
  switch (z->type) {
    case BTC_MSG_VERSION:
      return btc_version_read((btc_version_t *)z->body, xp, xn);
    case BTC_MSG_VERACK:
      return 1;
    case BTC_MSG_PING:
      return btc_ping_read((btc_ping_t *)z->body, xp, xn);
    case BTC_MSG_PONG:
      return btc_pong_read((btc_pong_t *)z->body, xp, xn);
    case BTC_MSG_GETADDR:
      return 1;
    case BTC_MSG_ADDR:
      return btc_addrs_read((btc_addrs_t *)z->body, xp, xn);
    case BTC_MSG_INV:
    case BTC_MSG_GETDATA:
    case BTC_MSG_NOTFOUND:
      return btc_zinv_read((btc_zinv_t *)z->body, xp, xn);
    case BTC_MSG_INV_FULL:
    case BTC_MSG_GETDATA_FULL:
    case BTC_MSG_NOTFOUND_FULL:
      return btc_inv_read((btc_inv_t *)z->body, xp, xn);
    case BTC_MSG_GETBLOCKS:
    case BTC_MSG_GETHEADERS:
      return btc_getblocks_read((btc_getblocks_t *)z->body, xp, xn);
    case BTC_MSG_HEADERS:
      return btc_headers_read((btc_headers_t *)z->body, xp, xn);
    case BTC_MSG_SENDHEADERS:
      return 1;
    case BTC_MSG_BLOCK:
    case BTC_MSG_BLOCK_BASE:
      return btc_block_read((btc_block_t *)z->body, xp, xn);
    case BTC_MSG_TX:
    case BTC_MSG_TX_BASE:
      return btc_tx_read((btc_tx_t *)z->body, xp, xn);
    case BTC_MSG_REJECT:
      return btc_reject_read((btc_reject_t *)z->body, xp, xn);
    case BTC_MSG_MEMPOOL:
      return 1;
    case BTC_MSG_FILTERLOAD:
      return btc_bloom_read((btc_bloom_t *)z->body, xp, xn);
    case BTC_MSG_FILTERADD:
      return btc_filteradd_read((btc_filteradd_t *)z->body, xp, xn);
    case BTC_MSG_FILTERCLEAR:
      return 1;
    case BTC_MSG_MERKLEBLOCK:
      return btc_merkleblock_read((btc_merkleblock_t *)z->body, xp, xn);
    case BTC_MSG_FEEFILTER:
      return btc_feefilter_read((btc_feefilter_t *)z->body, xp, xn);
    case BTC_MSG_SENDCMPCT:
      return btc_sendcmpct_read((btc_sendcmpct_t *)z->body, xp, xn);
    case BTC_MSG_CMPCTBLOCK:
    case BTC_MSG_CMPCTBLOCK_BASE:
      return btc_cmpct_read((btc_cmpct_t *)z->body, xp, xn);
    case BTC_MSG_GETBLOCKTXN:
      return btc_getblocktxn_read((btc_getblocktxn_t *)z->body, xp, xn);
    case BTC_MSG_BLOCKTXN:
    case BTC_MSG_BLOCKTXN_BASE:
      return btc_blocktxn_read((btc_blocktxn_t *)z->body, xp, xn);
    case BTC_MSG_UNKNOWN:
      return btc_unknown_read((btc_unknown_t *)z->body, xp, xn);
    default:
      return 0;
  }
}
