/*!
 * client.c - wallet client for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "client.h"

/*
 * Wallet Client
 */

void
btc_wclient_init(btc_wclient_t *client) {
  memset(client, 0, sizeof(*client));
}

int
btc_wclient_open(const btc_wclient_t *client) {
  if (client->open == NULL)
    return 1;

  return client->open(client->state);
}

int
btc_wclient_close(const btc_wclient_t *client) {
  if (client->close == NULL)
    return 1;

  return client->close(client->state);
}

const btc_entry_t *
btc_wclient_tip(const btc_wclient_t *client) {
  if (client->tip == NULL)
    return NULL;

  return client->tip(client->state);
}

const btc_entry_t *
btc_wclient_by_hash(const btc_wclient_t *client, const uint8_t *hash) {
  if (client->by_hash == NULL)
    return NULL;

  return client->by_hash(client->state, hash);
}

const btc_entry_t *
btc_wclient_by_height(const btc_wclient_t *client, int32_t height) {
  if (client->by_height == NULL)
    return NULL;

  return client->by_height(client->state, height);
}

btc_block_t *
btc_wclient_get_block(const btc_wclient_t *client, const btc_entry_t *entry) {
  if (client->get_block == NULL)
    return NULL;

  return client->get_block(client->state, entry);
}

void
btc_wclient_send(const btc_wclient_t *client, const btc_tx_t *tx) {
  if (client->send != NULL)
    client->send(client->state, tx);
}

void
btc_wclient_log(const btc_wclient_t *client,
                int level,
                const char *fmt,
                va_list ap) {
  if (client->log != NULL)
    client->log(client->state, level, fmt, ap);
}
