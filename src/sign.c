/*!
 * sign.c - tx signing functions for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mako/address.h>
#include <mako/coins.h>
#include <mako/consensus.h>
#include <mako/crypto/ecc.h>
#include <mako/crypto/hash.h>
#include <mako/map.h>
#include <mako/policy.h>
#include <mako/script.h>
#include <mako/tx.h>
#include <mako/util.h>
#include <mako/vector.h>
#include "impl.h"
#include "internal.h"

/*
 * Key Pair
 */

typedef struct btc_keypair_s {
  uint8_t priv[32];
  uint8_t pub33[33];
  uint8_t pub65[65];
  uint8_t hash33[20];
  uint8_t hash65[20];
} btc_keypair_t;

static int
btc_keypair_init(btc_keypair_t *key, const uint8_t *priv) {
  if (!btc_ecdsa_pubkey_create(key->pub65, priv, 0))
    return 0;

  if (!btc_ecdsa_pubkey_convert(key->pub33, key->pub65, 65, 1))
    return 0;

  btc_hash160(key->hash33, key->pub33, 33);
  btc_hash160(key->hash65, key->pub65, 65);

  memcpy(key->priv, priv, 32);

  return 1;
}

static void
btc_keypair_clear(btc_keypair_t *key) {
  btc_memzero(key->priv, 32);
}

static int
btc_keypair_matches(const btc_keypair_t *key,
                    const uint8_t *pub,
                    size_t pub_len) {
  if (pub_len == 33)
    return memcmp(key->pub33, pub, 33) == 0;

  if (pub_len == 65)
    return memcmp(key->pub65, pub, 65) == 0;

  return 0;
}

static int
btc_keypair_pubkey(const uint8_t **pub,
                   size_t *pub_len,
                   const btc_keypair_t *key,
                   const uint8_t *hash) {
  if (memcmp(hash, key->hash33, 20) == 0) {
    *pub = key->pub33;
    *pub_len = 33;
    return 1;
  }

  if (memcmp(hash, key->hash65, 20) == 0) {
    *pub = key->pub65;
    *pub_len = 65;
    return 1;
  }

  return 0;
}

static int
btc_keypair_redeem(btc_script_t *script,
                   const btc_keypair_t *key,
                   const uint8_t *hash) {
  uint8_t expect[20];

  btc_script_set_p2wpkh(script, key->hash33);
  btc_script_hash160(expect, script);

  if (memcmp(hash, expect, 20) == 0)
    return 1;

  btc_script_set_p2wpkh(script, key->hash65);
  btc_script_hash160(expect, script);

  if (memcmp(hash, expect, 20) == 0)
    return 1;

  return 0;
}

/*
 * Signing
 */

static int
btc_tx_signature(uint8_t *sig,
                 size_t *sig_len,
                 const btc_tx_t *tx,
                 size_t index,
                 const btc_script_t *prev,
                 int64_t value,
                 const uint8_t *priv,
                 int type,
                 int version,
                 btc_tx_cache_t *cache) {
  uint8_t msg[32];
  uint8_t tmp[64];

  btc_tx_sighash(msg,
                 tx,
                 index,
                 prev,
                 value,
                 type,
                 version,
                 cache);

  if (!btc_ecdsa_sign(tmp, NULL, msg, 32, priv))
    return 0;

  CHECK(btc_ecdsa_sig_export(sig, sig_len, tmp));
  CHECK(*sig_len <= 72);

  sig[(*sig_len)++] = type;

  return 1;
}

static int
btc_tx_sign_p2pk(btc_tx_t *tx,
                 size_t index,
                 const btc_output_t *coin,
                 const btc_keypair_t *key,
                 int type,
                 btc_tx_cache_t *cache) {
  btc_input_t *input = tx->inputs.items[index];
  size_t pub_len, sig_len;
  btc_writer_t writer;
  const uint8_t *pub;
  uint8_t sig[73];

  if (!btc_script_get_p2pk(&pub, &pub_len, &coin->script))
    return 0;

  if (!btc_keypair_matches(key, pub, pub_len))
    return 0;

  CHECK(btc_tx_signature(sig,
                         &sig_len,
                         tx,
                         index,
                         &coin->script,
                         coin->value,
                         key->priv,
                         type,
                         0,
                         cache));

  btc_writer_init(&writer);
  btc_writer_push_data(&writer, sig, sig_len);
  btc_writer_compile(&input->script, &writer);
  btc_writer_clear(&writer);

  return 1;
}

static int
btc_tx_sign_p2pkh(btc_tx_t *tx,
                  size_t index,
                  const btc_output_t *coin,
                  const btc_keypair_t *key,
                  int type,
                  btc_tx_cache_t *cache) {
  btc_input_t *input = tx->inputs.items[index];
  const uint8_t *hash, *pub;
  size_t pub_len, sig_len;
  btc_writer_t writer;
  uint8_t sig[73];

  if (!btc_script_get_p2pkh(&hash, &coin->script))
    return 0;

  if (!btc_keypair_pubkey(&pub, &pub_len, key, hash))
    return 0;

  CHECK(btc_tx_signature(sig,
                         &sig_len,
                         tx,
                         index,
                         &coin->script,
                         coin->value,
                         key->priv,
                         type,
                         0,
                         cache));

  btc_writer_init(&writer);
  btc_writer_push_data(&writer, sig, sig_len);
  btc_writer_push_data(&writer, pub, pub_len);
  btc_writer_compile(&input->script, &writer);
  btc_writer_clear(&writer);

  return 1;
}

static int
btc_tx_sign_p2wpkh(btc_tx_t *tx,
                   size_t index,
                   const btc_output_t *coin,
                   const btc_keypair_t *key,
                   int type,
                   btc_tx_cache_t *cache) {
  btc_input_t *input = tx->inputs.items[index];
  const uint8_t *hash, *pub;
  size_t pub_len, sig_len;
  btc_script_t redeem;
  uint8_t sig[73];
  uint8_t tmp[25];

  if (!btc_script_get_p2wpkh(&hash, &coin->script))
    return 0;

  if (!btc_keypair_pubkey(&pub, &pub_len, key, hash))
    return 0;

  btc_script_rwset(&redeem, tmp, sizeof(tmp));
  btc_script_set_p2pkh(&redeem, hash);

  CHECK(btc_tx_signature(sig,
                         &sig_len,
                         tx,
                         index,
                         &redeem,
                         coin->value,
                         key->priv,
                         type,
                         1,
                         cache));

  btc_stack_reset(&input->witness);
  btc_stack_push_data(&input->witness, sig, sig_len);
  btc_stack_push_data(&input->witness, pub, pub_len);

  return 1;
}

static int
btc_tx_sign_p2sh(btc_tx_t *tx,
                 size_t index,
                 const btc_output_t *coin,
                 const btc_keypair_t *key,
                 int type,
                 btc_tx_cache_t *cache) {
  btc_input_t *input = tx->inputs.items[index];
  const uint8_t *hash;
  btc_writer_t writer;
  btc_output_t output;
  uint8_t tmp[22];

  if (!btc_script_get_p2sh(&hash, &coin->script))
    return 0;

  output.value = coin->value;

  btc_script_rwset(&output.script, tmp, sizeof(tmp));

  if (!btc_keypair_redeem(&output.script, key, hash))
    return 0;

  CHECK(btc_tx_sign_p2wpkh(tx, index, &output, key, type, cache));

  btc_writer_init(&writer);
  btc_writer_push_data(&writer, output.script.data, output.script.length);
  btc_writer_compile(&input->script, &writer);
  btc_writer_clear(&writer);

  return 1;
}

static int
btc_tx_sign_input(btc_tx_t *tx,
                  size_t index,
                  const btc_output_t *coin,
                  const btc_keypair_t *key,
                  int type,
                  btc_tx_cache_t *cache) {
  if (btc_tx_sign_p2pk(tx, index, coin, key, type, cache))
    return 1;

  if (btc_tx_sign_p2pkh(tx, index, coin, key, type, cache))
    return 1;

  if (btc_tx_sign_p2wpkh(tx, index, coin, key, type, cache))
    return 1;

  if (btc_tx_sign_p2sh(tx, index, coin, key, type, cache))
    return 1;

  return 0;
}

int
btc_tx_sign_step(btc_tx_t *tx,
                 const btc_view_t *view,
                 const uint8_t *priv,
                 btc_tx_cache_t *cache) {
  const btc_input_t *input;
  const btc_coin_t *coin;
  btc_keypair_t key;
  int total = 0;
  size_t i;

  if (!btc_keypair_init(&key, priv))
    return 0;

  for (i = 0; i < tx->inputs.length; i++) {
    input = tx->inputs.items[i];
    coin = btc_view_get(view, &input->prevout);

    if (coin == NULL)
      continue;

    total += btc_tx_sign_input(tx,
                               i,
                               &coin->output,
                               &key,
                               BTC_SIGHASH_ALL,
                               cache);
  }

  btc_keypair_clear(&key);

  return total;
}

int
btc_tx_sign(btc_tx_t *tx,
            const btc_view_t *view,
            btc_derive_f *derive,
            void *arg) {
  btc_vector_t *addrs = btc_tx_input_addrs(tx, view);
  btc_tx_cache_t cache;
  uint8_t priv[32];
  int total = 0;
  size_t i;

  memset(&cache, 0, sizeof(cache));

  for (i = 0; i < addrs->length; i++) {
    const btc_address_t *addr = addrs->items[i];

    if (!derive(priv, addr, arg))
      continue;

    total += btc_tx_sign_step(tx, view, priv, &cache);

    btc_memzero(priv, 32);
  }

  for (i = 0; i < addrs->length; i++)
    btc_address_destroy(addrs->items[i]);

  btc_vector_destroy(addrs);

  return total;
}
