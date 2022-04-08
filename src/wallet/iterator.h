/*!
 * iterator.h - wallet iterators for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_WALLET_ITERATOR_H_
#define BTC_WALLET_ITERATOR_H_

#include <lcdb.h>
#include <wallet/iterator.h>

/*
 * Account Iterator
 */

btc_acctiter_t *
btc_acctiter_create(ldb_t *db);

/*
 * Address Iterator
 */

btc_addriter_t *
btc_addriter_create(ldb_t *db);

/*
 * Coin Iterator
 */

btc_coiniter_t *
btc_coiniter_create(ldb_t *db);

/*
 * Transaction Iterator
 */

btc_txiter_t *
btc_txiter_create(ldb_t *db);

#endif /* BTC_WALLET_ITERATOR_H_ */
