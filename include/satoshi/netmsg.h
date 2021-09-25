/*!
 * netmsg.h - network messages for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_NETMSG_H
#define BTC_NETMSG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "impl.h"
#include "types.h"

/*
 * Constants
 */

enum btc_msgtype {
  BTC_MSG_VERSION,
  BTC_MSG_VERACK,
  BTC_MSG_PING,
  BTC_MSG_PONG,
  BTC_MSG_GETADDR,
  BTC_MSG_ADDR,
  BTC_MSG_INV,
  BTC_MSG_GETDATA,
  BTC_MSG_NOTFOUND,
  BTC_MSG_GETBLOCKS,
  BTC_MSG_GETHEADERS,
  BTC_MSG_HEADERS,
  BTC_MSG_SENDHEADERS,
  BTC_MSG_BLOCK,
  BTC_MSG_TX,
  BTC_MSG_REJECT,
  BTC_MSG_MEMPOOL,
  BTC_MSG_FILTERLOAD,
  BTC_MSG_FILTERADD,
  BTC_MSG_FILTERCLEAR,
  BTC_MSG_MERKLEBLOCK,
  BTC_MSG_FEEFILTER,
  BTC_MSG_SENDCMPCT,
  BTC_MSG_CMPCTBLOCK,
  BTC_MSG_GETBLOCKTXN,
  BTC_MSG_BLOCKTXN,
  BTC_MSG_UNKNOWN,
  /* Internal */
  BTC_MSG_BLOCK_BASE,
  BTC_MSG_TX_BASE,
  BTC_MSG_INTERNAL,
  BTC_MSG_DATA
};

enum btc_invtype {
  BTC_INV_TX = 1,
  BTC_INV_BLOCK = 2,
  BTC_INV_FILTERED_BLOCK = 3,
  BTC_INV_CMPCT_BLOCK = 4,
  BTC_INV_WITNESS_TX = 1 | (1 << 30),
  BTC_INV_WITNESS_BLOCK = 2 | (1 << 30),
  BTC_INV_WITNESS_FILTERED_BLOCK = 3 | (1 << 30),
  BTC_INV_WITNESS_FLAG = 1 << 30
};

enum btc_reject_code {
  BTC_REJECT_MALFORMED = 0x01,
  BTC_REJECT_INVALID = 0x10,
  BTC_REJECT_OBSOLETE = 0x11,
  BTC_REJECT_DUPLICATE = 0x12,
  BTC_REJECT_NONSTANDARD = 0x40,
  BTC_REJECT_DUST = 0x41,
  BTC_REJECT_INSUFFICIENTFEE = 0x42,
  BTC_REJECT_CHECKPOINT = 0x43,
  /* Internal codes (NOT FOR USE ON NETWORK) */
  BTC_REJECT_INTERNAL = 0x100,
  BTC_REJECT_HIGHFEE = 0x101,
  BTC_REJECT_ALREADYKNOWN = 0x102,
  BTC_REJECT_CONFLICT = 0x103
};

/*
 * Types
 */

typedef struct btc_version_s {
  int32_t version;
  uint64_t services;
  int64_t time;
  btc_netaddr_t remote;
  btc_netaddr_t local;
  uint64_t nonce;
  char agent[256 + 1];
  int32_t height;
  uint8_t no_relay;
} btc_version_t;

typedef struct btc_ping_s {
  uint64_t nonce;
} btc_ping_t;

typedef btc_ping_t btc_pong_t;

typedef struct btc_addrs_s {
  btc_netaddr_t **items;
  size_t alloc;
  size_t length;
} btc_addrs_t;

typedef struct btc_invitem_s {
  uint32_t type;
  uint8_t hash[32];
  struct btc_invitem_s *next;
} btc_invitem_t;

typedef struct btc_inv_s {
  btc_invitem_t **items;
  size_t alloc;
  size_t length;
} btc_inv_t;

typedef btc_inv_t btc_getdata_t;
typedef btc_inv_t btc_notfound_t;

typedef struct btc_getblocks_s {
  uint32_t version;
  btc_vector_t locator;
  uint8_t stop[32];
} btc_getblocks_t;

typedef btc_getblocks_t btc_getheaders_t;

typedef struct btc_headers_s {
  btc_header_t **items;
  size_t alloc;
  size_t length;
} btc_headers_t;

typedef struct btc_reject_s {
  char message[12 + 1];
  uint8_t code;
  char reason[111 + 1];
  uint8_t hash[32];
} btc_reject_t;

typedef struct btc_filteradd_s {
  uint8_t data[256];
  size_t length;
} btc_filteradd_t;

typedef struct btc_feefilter_s {
  int64_t rate;
} btc_feefilter_t;

typedef struct btc_sendcmpct_s {
  uint8_t mode;
  uint64_t version;
} btc_sendcmpct_t;

typedef struct btc_unknown_s {
  uint8_t *data;
  size_t length;
} btc_unknown_t;

typedef struct btc_msg_s {
  enum btc_msgtype type;
  char cmd[12];
  void *body;
} btc_msg_t;

/*
 * Version
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_version, BTC_EXTERN)

BTC_EXTERN void
btc_version_init(btc_version_t *msg);

BTC_EXTERN void
btc_version_clear(btc_version_t *msg);

BTC_EXTERN void
btc_version_copy(btc_version_t *z, const btc_version_t *x);

BTC_EXTERN size_t
btc_version_size(const btc_version_t *x);

BTC_EXTERN uint8_t *
btc_version_write(uint8_t *zp, const btc_version_t *x);

BTC_EXTERN int
btc_version_read(btc_version_t *z, const uint8_t **xp, size_t *xn);

/*
 * Verack
 */

/* empty message */

/*
 * Ping
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_ping, BTC_EXTERN)

BTC_EXTERN void
btc_ping_init(btc_ping_t *msg);

BTC_EXTERN void
btc_ping_clear(btc_ping_t *msg);

BTC_EXTERN void
btc_ping_copy(btc_ping_t *z, const btc_ping_t *x);

BTC_EXTERN size_t
btc_ping_size(const btc_ping_t *x);

BTC_EXTERN uint8_t *
btc_ping_write(uint8_t *zp, const btc_ping_t *x);

BTC_EXTERN int
btc_ping_read(btc_ping_t *z, const uint8_t **xp, size_t *xn);

/*
 * Pong
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_pong, BTC_EXTERN)

BTC_EXTERN void
btc_pong_init(btc_pong_t *msg);

BTC_EXTERN void
btc_pong_clear(btc_pong_t *msg);

BTC_EXTERN void
btc_pong_copy(btc_pong_t *z, const btc_pong_t *x);

BTC_EXTERN size_t
btc_pong_size(const btc_pong_t *x);

BTC_EXTERN uint8_t *
btc_pong_write(uint8_t *zp, const btc_pong_t *x);

BTC_EXTERN int
btc_pong_read(btc_pong_t *z, const uint8_t **xp, size_t *xn);

/*
 * GetAddr
 */

/* empty message */

/*
 * Addr
 */

BTC_DEFINE_SERIALIZABLE_VECTOR(btc_addrs, btc_netaddr, BTC_EXTERN)

/*
 * Inv Item
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_invitem, BTC_EXTERN)

BTC_EXTERN void
btc_invitem_init(btc_invitem_t *item);

BTC_EXTERN void
btc_invitem_clear(btc_invitem_t *item);

BTC_EXTERN void
btc_invitem_copy(btc_invitem_t *z, const btc_invitem_t *x);

BTC_EXTERN void
btc_invitem_set(btc_invitem_t *z, uint32_t type, const uint8_t *hash);

BTC_EXTERN size_t
btc_invitem_size(const btc_invitem_t *x);

BTC_EXTERN uint8_t *
btc_invitem_write(uint8_t *zp, const btc_invitem_t *x);

BTC_EXTERN int
btc_invitem_read(btc_invitem_t *z, const uint8_t **xp, size_t *xn);

/*
 * Inv
 */

BTC_DEFINE_SERIALIZABLE_VECTOR(btc_inv, btc_invitem, BTC_EXTERN)

BTC_EXTERN void
btc_inv_push_item(btc_inv_t *inv, uint32_t type, const uint8_t *hash);

/*
 * GetData
 */

/* inherits btc_inv_t */

/*
 * NotFound
 */

/* inherits btc_inv_t */

/*
 * GetBlocks
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_getblocks, BTC_EXTERN)

BTC_EXTERN void
btc_getblocks_init(btc_getblocks_t *msg);

BTC_EXTERN void
btc_getblocks_uninit(btc_getblocks_t *msg);

BTC_EXTERN void
btc_getblocks_clear(btc_getblocks_t *msg);

BTC_EXTERN void
btc_getblocks_copy(btc_getblocks_t *z, const btc_getblocks_t *x);

BTC_EXTERN size_t
btc_getblocks_size(const btc_getblocks_t *x);

BTC_EXTERN uint8_t *
btc_getblocks_write(uint8_t *zp, const btc_getblocks_t *x);

BTC_EXTERN int
btc_getblocks_read(btc_getblocks_t *z, const uint8_t **xp, size_t *xn);

/*
 * GetHeaders
 */

/* inherits btc_getblocks_t */

/*
 * Headers
 */

BTC_DEFINE_SERIALIZABLE_VECTOR(btc_headers, btc_header, BTC_EXTERN)

/*
 * SendHeaders
 */

/* empty message */

/*
 * Block
 */

/* already implemented */

/*
 * TX
 */

/* already implemented */

/*
 * Reject
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_reject, BTC_EXTERN)

BTC_EXTERN void
btc_reject_init(btc_reject_t *msg);

BTC_EXTERN void
btc_reject_clear(btc_reject_t *msg);

BTC_EXTERN void
btc_reject_copy(btc_reject_t *z, const btc_reject_t *x);

BTC_EXTERN void
btc_reject_set_code(btc_reject_t *z, const char *code);

BTC_EXTERN const char *
btc_reject_get_code(const btc_reject_t *x);

BTC_EXTERN size_t
btc_reject_size(const btc_reject_t *x);

BTC_EXTERN uint8_t *
btc_reject_write(uint8_t *zp, const btc_reject_t *x);

BTC_EXTERN int
btc_reject_read(btc_reject_t *z, const uint8_t **xp, size_t *xn);

/*
 * Mempool
 */

/* empty message */

/*
 * FilterLoad
 */

/* TODO */

/*
 * FilterAdd
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_filteradd, BTC_EXTERN)

BTC_EXTERN void
btc_filteradd_init(btc_filteradd_t *msg);

BTC_EXTERN void
btc_filteradd_clear(btc_filteradd_t *msg);

BTC_EXTERN void
btc_filteradd_copy(btc_filteradd_t *z, const btc_filteradd_t *x);

BTC_EXTERN size_t
btc_filteradd_size(const btc_filteradd_t *x);

BTC_EXTERN uint8_t *
btc_filteradd_write(uint8_t *zp, const btc_filteradd_t *x);

BTC_EXTERN int
btc_filteradd_read(btc_filteradd_t *z, const uint8_t **xp, size_t *xn);

/*
 * FilterClear
 */

/* empty message */

/*
 * MerkleBlock
 */

/* TODO */

/*
 * FeeFilter
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_feefilter, BTC_EXTERN)

BTC_EXTERN void
btc_feefilter_init(btc_feefilter_t *msg);

BTC_EXTERN void
btc_feefilter_clear(btc_feefilter_t *msg);

BTC_EXTERN void
btc_feefilter_copy(btc_feefilter_t *z, const btc_feefilter_t *x);

BTC_EXTERN size_t
btc_feefilter_size(const btc_feefilter_t *x);

BTC_EXTERN uint8_t *
btc_feefilter_write(uint8_t *zp, const btc_feefilter_t *x);

BTC_EXTERN int
btc_feefilter_read(btc_feefilter_t *z, const uint8_t **xp, size_t *xn);

/*
 * SendCmpct
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_sendcmpct, BTC_EXTERN)

BTC_EXTERN void
btc_sendcmpct_init(btc_sendcmpct_t *msg);

BTC_EXTERN void
btc_sendcmpct_clear(btc_sendcmpct_t *msg);

BTC_EXTERN void
btc_sendcmpct_copy(btc_sendcmpct_t *z, const btc_sendcmpct_t *x);

BTC_EXTERN size_t
btc_sendcmpct_size(const btc_sendcmpct_t *x);

BTC_EXTERN uint8_t *
btc_sendcmpct_write(uint8_t *zp, const btc_sendcmpct_t *x);

BTC_EXTERN int
btc_sendcmpct_read(btc_sendcmpct_t *z, const uint8_t **xp, size_t *xn);

/*
 * CmpctBlock
 */

/* TODO */

/*
 * GetBlockTxn
 */

/* TODO */

/*
 * BlockTxn
 */

/* TODO */

/*
 * Unknown
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_unknown, BTC_EXTERN)

BTC_EXTERN void
btc_unknown_init(btc_unknown_t *msg);

BTC_EXTERN void
btc_unknown_clear(btc_unknown_t *msg);

BTC_EXTERN void
btc_unknown_copy(btc_unknown_t *z, const btc_unknown_t *x);

BTC_EXTERN size_t
btc_unknown_size(const btc_unknown_t *x);

BTC_EXTERN uint8_t *
btc_unknown_write(uint8_t *zp, const btc_unknown_t *x);

BTC_EXTERN int
btc_unknown_read(btc_unknown_t *z, const uint8_t **xp, size_t *xn);

/*
 * Message
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_msg, BTC_EXTERN)

BTC_EXTERN void
btc_msg_init(btc_msg_t *msg);

BTC_EXTERN void
btc_msg_clear(btc_msg_t *msg);

BTC_EXTERN void
btc_msg_copy(btc_msg_t *z, const btc_msg_t *x);

BTC_EXTERN void
btc_msg_set_type(btc_msg_t *msg, enum btc_msgtype type);

BTC_EXTERN void
btc_msg_set_cmd(btc_msg_t *msg, const char *cmd);

BTC_EXTERN void
btc_msg_alloc(btc_msg_t *msg);

BTC_EXTERN size_t
btc_msg_size(const btc_msg_t *x);

BTC_EXTERN uint8_t *
btc_msg_write(uint8_t *zp, const btc_msg_t *x);

BTC_EXTERN int
btc_msg_read(btc_msg_t *z, const uint8_t **xp, size_t *xn);

#ifdef __cplusplus
}
#endif

#endif /* BTC_NETMSG_H */
