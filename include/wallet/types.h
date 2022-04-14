/*!
 * types.h - wallet types for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_WALLET_TYPES_H
#define BTC_WALLET_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include "../mako/types.h"

/*
 * Constants
 */

#define BTC_NO_ACCOUNT ((uint32_t)-1)

/*
 * Types
 */

typedef struct btc_balance_s {
  int64_t tx;
  int64_t coin;
  int64_t confirmed;
  int64_t unconfirmed;
} btc_balance_t;

typedef struct btc_wclient_s {
  void *state;
  int (*open)(void *);
  int (*close)(void *);
  const btc_entry_t *(*tip)(void *);
  const btc_entry_t *(*by_hash)(void *, const uint8_t *);
  const btc_entry_t *(*by_height)(void *, int32_t);
  btc_block_t *(*get_block)(void *, const btc_entry_t *);
  void (*send)(void *, const btc_tx_t *);
  void (*log)(void *, int, const char *, va_list);
} btc_wclient_t;

typedef struct btc_path_s {
  uint32_t account;
  uint32_t change;
  uint32_t index;
} btc_path_t;

typedef struct btc_txmeta_s {
  uint64_t id;
  int32_t height;
  int64_t time;
  int64_t mtime;
  int32_t index;
  uint8_t block[32];
  uint32_t resolved;
  int64_t inpval;
} btc_txmeta_t;

typedef struct btc_walopt_s {
  const btc_wclient_t *client;
  int checkpoints;
  enum btc_bip32_type type;
  const btc_mnemonic_t *mnemonic;
  const btc_hdnode_t *chain;
} btc_walopt_t;

typedef struct btc_wallet_s btc_wallet_t;
typedef struct btc_acctiter_s btc_acctiter_t;
typedef struct btc_addriter_s btc_addriter_t;
typedef struct btc_coiniter_s btc_coiniter_t;
typedef struct btc_txiter_s btc_txiter_t;

#ifdef __cplusplus
}
#endif

#endif /* BTC_WALLET_TYPES_H */
