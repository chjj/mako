/*!
 * wallet.h - wallet for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_WALLET_H_
#define BTC_WALLET_H_

#include <wallet/wallet.h>
#include "types.h"

/*
 * Wallet
 */

void
btc_wallet_watch(btc_wallet_t *wallet, const uint8_t *hash, uint32_t index);

size_t
btc_wallet_size(const btc_wallet_t *wallet);

uint8_t *
btc_wallet_write(uint8_t *zp, const btc_wallet_t *x);

int
btc_wallet_read(btc_wallet_t *z, const uint8_t **xp, size_t *xn);

size_t
btc_wallet_export(uint8_t *zp, const btc_wallet_t *x);

int
btc_wallet_import(btc_wallet_t *z, const uint8_t *xp, size_t xn);

#endif /* BTC_WALLET_H_ */
