/*!
 * client.h - wallet client for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_WALLET_CLIENT_H
#define BTC_WALLET_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"

/*
 * Wallet Client
 */

void
btc_wclient_init(btc_wclient_t *client);

int
btc_wclient_open(const btc_wclient_t *client);

int
btc_wclient_close(const btc_wclient_t *client);

const btc_entry_t *
btc_wclient_tip(const btc_wclient_t *client);

const btc_entry_t *
btc_wclient_by_hash(const btc_wclient_t *client, const uint8_t *hash);

const btc_entry_t *
btc_wclient_by_height(const btc_wclient_t *client, int32_t height);

btc_block_t *
btc_wclient_get_block(const btc_wclient_t *client, const btc_entry_t *entry);

void
btc_wclient_send(const btc_wclient_t *client, const btc_tx_t *tx);

void
btc_wclient_log(const btc_wclient_t *client,
                int level,
                const char *fmt,
                va_list ap);

#endif /* BTC_WALLET_CLIENT_H */
