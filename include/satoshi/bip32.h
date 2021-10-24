/*!
 * bip32.h - bip32 for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_BIP32_H
#define BTC_BIP32_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "types.h"
#include "common.h"

/*
 * Constants
 */

/* https://github.com/satoshilabs/slips/blob/master/slip-0132.md */
enum btc_bip32_type {
  BTC_BIP32_LEGACY = 0, /*  xpub/xprv, m/44' */
  BTC_BIP32_NESTED_P2WPKH = 1, /* ypub/yprv, m/49' */
  BTC_BIP32_P2WPKH = 2, /* zpub/zprv, m/84' */
  BTC_BIP32_NESTED_P2WSH = 3, /* Ypub/Yprv */
  BTC_BIP32_P2WSH = 4 /* Zpub/Zprv */
};

#define BTC_BIP32_HARDEN 0x80000000
#define BTC_BIP32_MAX_DEPTH 255
#define BTC_BIP32_STRLEN 115
#define BTC_HDNODE_SIZE 82

/*
 * Types
 */

typedef struct btc_hdnode_s {
  enum btc_bip32_type type;
  uint8_t depth;
  uint32_t parent;
  uint32_t index;
  uint8_t chain[32];
  uint8_t seckey[32];
  uint8_t pubkey[33];
} btc_hdnode_t;

/*
 * HD Private
 */

BTC_EXTERN void
btc_hdpriv_init(btc_hdnode_t *node);

BTC_EXTERN void
btc_hdpriv_clear(btc_hdnode_t *node);

BTC_EXTERN void
btc_hdpriv_copy(btc_hdnode_t *z, const btc_hdnode_t *x);

BTC_EXTERN int
btc_hdpriv_set(btc_hdnode_t *node,
               enum btc_bip32_type type,
               const uint8_t *seckey,
               const uint8_t *entropy);

BTC_EXTERN void
btc_hdpriv_generate(btc_hdnode_t *node, enum btc_bip32_type type);

BTC_EXTERN int
btc_hdpriv_derive(btc_hdnode_t *child,
                  const btc_hdnode_t *node,
                  uint32_t index,
                  int harden);

BTC_EXTERN int
btc_hdpriv_path(btc_hdnode_t *child,
                const btc_hdnode_t *node,
                const char *path);

BTC_EXTERN int
btc_hdpriv_account(btc_hdnode_t *child,
                   const btc_hdnode_t *node,
                   uint32_t purpose,
                   uint32_t type,
                   uint32_t account);

BTC_EXTERN int
btc_hdpriv_leaf(btc_hdnode_t *child,
                const btc_hdnode_t *node,
                uint32_t branch,
                uint32_t index);

BTC_EXTERN void
btc_hdpriv_export(uint8_t *data,
                  const btc_hdnode_t *node,
                  const btc_network_t *network);

BTC_EXTERN int
btc_hdpriv_import(btc_hdnode_t *node,
                  const uint8_t *data,
                  const btc_network_t *network);

BTC_EXTERN size_t
btc_hdpriv_size(const btc_hdnode_t *node);

BTC_EXTERN uint8_t *
btc_hdpriv_write(uint8_t *zp,
                 const btc_hdnode_t *x,
                 const btc_network_t *network);

BTC_EXTERN int
btc_hdpriv_read(btc_hdnode_t *z,
                const uint8_t **xp,
                size_t *xn,
                const btc_network_t *network);

BTC_EXTERN void
btc_hdpriv_get_str(char *str,
                   const btc_hdnode_t *node,
                   const btc_network_t *network);

BTC_EXTERN int
btc_hdpriv_set_str(btc_hdnode_t *node,
                   const char *str,
                   const btc_network_t *network);

/*
 * HD Public
 */

BTC_EXTERN void
btc_hdpub_init(btc_hdnode_t *node);

BTC_EXTERN void
btc_hdpub_clear(btc_hdnode_t *node);

BTC_EXTERN void
btc_hdpub_copy(btc_hdnode_t *z, const btc_hdnode_t *x);

BTC_EXTERN int
btc_hdpub_set(btc_hdnode_t *node,
              enum btc_bip32_type type,
              const uint8_t *pubkey,
              const uint8_t *entropy);

BTC_EXTERN void
btc_hdpub_set_hdpriv(btc_hdnode_t *z, const btc_hdnode_t *x);

BTC_EXTERN int
btc_hdpub_derive(btc_hdnode_t *child,
                 const btc_hdnode_t *node,
                 uint32_t index);

BTC_EXTERN int
btc_hdpub_path(btc_hdnode_t *child,
               const btc_hdnode_t *node,
               const char *path);

BTC_EXTERN int
btc_hdpub_leaf(btc_hdnode_t *child,
               const btc_hdnode_t *node,
               uint32_t branch,
               uint32_t index);

BTC_EXTERN void
btc_hdpub_export(uint8_t *data,
                 const btc_hdnode_t *node,
                 const btc_network_t *network);

BTC_EXTERN int
btc_hdpub_import(btc_hdnode_t *node,
                 const uint8_t *data,
                 const btc_network_t *network);

BTC_EXTERN size_t
btc_hdpub_size(const btc_hdnode_t *node);

BTC_EXTERN uint8_t *
btc_hdpub_write(uint8_t *zp,
                const btc_hdnode_t *x,
                const btc_network_t *network);

BTC_EXTERN int
btc_hdpub_read(btc_hdnode_t *z,
               const uint8_t **xp,
               size_t *xn,
               const btc_network_t *network);

BTC_EXTERN void
btc_hdpub_get_str(char *str,
                  const btc_hdnode_t *node,
                  const btc_network_t *network);

BTC_EXTERN int
btc_hdpub_set_str(btc_hdnode_t *node,
                  const char *str,
                  const btc_network_t *network);

#ifdef __cplusplus
}
#endif

#endif /* BTC_BIP32_H */
