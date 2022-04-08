/*!
 * iterator.h - wallet iterator for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_WALLET_ITERATOR_H
#define BTC_WALLET_ITERATOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"

/*
 * Iterator Macros
 */

#define btc_acctiter_range(it, min, max)                                  \
  for (btc_acctiter_seek(it, min);                                        \
       btc_acctiter_valid(it) && btc_acctiter_key(it) <= (unsigned)(max); \
       btc_acctiter_next(it))

#define btc_acctiter_each(it) btc_acctiter_range(it, 0, -1)

#define btc_addriter_range(it, min) \
  for (btc_addriter_seek(it, min);  \
       btc_addriter_valid(it);      \
       btc_addriter_next(it))

#define btc_addriter_each(it) btc_addriter_range(it, 0)

#define btc_coiniter_range(it, min) \
  for (btc_coiniter_seek(it, min);  \
       btc_coiniter_valid(it);      \
       btc_coiniter_next(it))

#define btc_coiniter_each(it) btc_coiniter_range(it, 0)

#define btc_txiter_range(it, min, max)                           \
  for (btc_txiter_seek_ge(it, min);                              \
       btc_txiter_valid(it) && btc_txiter_compare(it, max) <= 0; \
       btc_txiter_next(it))

#define btc_txiter_reverse(it, max, min)                         \
  for (btc_txiter_seek_le(it, max);                              \
       btc_txiter_valid(it) && btc_txiter_compare(it, min) >= 0; \
       btc_txiter_prev(it))

#define btc_txiter_each(it) btc_txiter_range(it, 0, -1)
#define btc_txiter_backwards(it) btc_txiter_reverse(it, -1, 0)

/*
 * Account Iterator
 */

void
btc_acctiter_destroy(btc_acctiter_t *iter);

int
btc_acctiter_valid(btc_acctiter_t *iter);

void
btc_acctiter_seek(btc_acctiter_t *iter, const char *name);

void
btc_acctiter_seek_gt(btc_acctiter_t *iter, const char *name);

void
btc_acctiter_first(btc_acctiter_t *iter);

void
btc_acctiter_next(btc_acctiter_t *iter);

uint32_t
btc_acctiter_index(btc_acctiter_t *iter);

const char *
btc_acctiter_key(btc_acctiter_t *iter);

btc_balance_t *
btc_acctiter_value(btc_acctiter_t *iter);

/*
 * Address Iterator
 */

void
btc_addriter_destroy(btc_addriter_t *iter);

void
btc_addriter_account(btc_addriter_t *iter, uint32_t account);

int
btc_addriter_valid(btc_addriter_t *iter);

void
btc_addriter_seek(btc_addriter_t *iter, const btc_address_t *target);

void
btc_addriter_seek_gt(btc_addriter_t *iter, const btc_address_t *target);

void
btc_addriter_first(btc_addriter_t *iter);

void
btc_addriter_next(btc_addriter_t *iter);

btc_address_t *
btc_addriter_key(btc_addriter_t *iter);

btc_path_t *
btc_addriter_value(btc_addriter_t *iter);

/*
 * Coin Iterator
 */

void
btc_coiniter_destroy(btc_coiniter_t *iter);

void
btc_coiniter_account(btc_coiniter_t *iter, uint32_t account);

int
btc_coiniter_valid(btc_coiniter_t *iter);

void
btc_coiniter_seek(btc_coiniter_t *iter, const btc_outpoint_t *target);

void
btc_coiniter_seek_gt(btc_coiniter_t *iter, const btc_outpoint_t *target);

void
btc_coiniter_first(btc_coiniter_t *iter);

void
btc_coiniter_next(btc_coiniter_t *iter);

btc_outpoint_t *
btc_coiniter_key(btc_coiniter_t *iter);

btc_coin_t *
btc_coiniter_value(btc_coiniter_t *iter);

/*
 * Transaction Iterator
 */

void
btc_txiter_destroy(btc_txiter_t *iter);

void
btc_txiter_account(btc_txiter_t *iter, uint32_t account);

void
btc_txiter_start(btc_txiter_t *iter, uint32_t height);

int
btc_txiter_valid(btc_txiter_t *iter);

void
btc_txiter_seek(btc_txiter_t *iter, uint64_t id);

void
btc_txiter_seek_ge(btc_txiter_t *iter, uint64_t id);

void
btc_txiter_seek_gt(btc_txiter_t *iter, uint64_t id);

void
btc_txiter_seek_le(btc_txiter_t *iter, uint64_t id);

void
btc_txiter_seek_lt(btc_txiter_t *iter, uint64_t id);

void
btc_txiter_first(btc_txiter_t *iter);

void
btc_txiter_last(btc_txiter_t *iter);

void
btc_txiter_next(btc_txiter_t *iter);

void
btc_txiter_prev(btc_txiter_t *iter);

int
btc_txiter_compare(const btc_txiter_t *iter, uint64_t key);

int32_t
btc_txiter_height(const btc_txiter_t *iter);

const uint8_t *
btc_txiter_hash(const btc_txiter_t *iter);

uint64_t
btc_txiter_key(const btc_txiter_t *iter);

btc_txmeta_t *
btc_txiter_meta(btc_txiter_t *iter);

btc_tx_t *
btc_txiter_value(btc_txiter_t *iter);

#ifdef __cplusplus
}
#endif

#endif /* BTC_WALLET_ITERATOR_H */
