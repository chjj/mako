/*!
 * t-bip32.c - bip32 tests for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mako/bip32.h>
#include <mako/encoding.h>
#include <mako/network.h>
#include <mako/util.h>
#include "lib/tests.h"
#include "data/bip32_vectors.h"

/*
 * Tests
 */

static void
test_vectors(void) {
  char str1[BTC_BIP32_STRLEN + 1];
  char str2[BTC_BIP32_STRLEN + 1];
  btc_hdnode_t key, pub, prv;
  btc_hdnode_t master;
  uint8_t seed[64];
  size_t i, j;

  for (i = 0; i < lengthof(bip32_vectors); i++) {
    const bip32_vector_t *vector = &bip32_vectors[i];
    size_t len = strlen(vector->seed);

    ASSERT(btc_base16_decode(seed, vector->seed, len));

    ASSERT(btc_hdpriv_set_seed(&master, BTC_BIP32_STANDARD, seed, len / 2));

    for (j = 0; j < lengthof(vector->derives); j++) {
      const key_vector_t *info = &vector->derives[j];

      ASSERT(btc_hdpub_set_str(&pub, info->pub, btc_mainnet));
      ASSERT(btc_hdpriv_set_str(&prv, info->prv, btc_mainnet));

      ASSERT(btc_hdpriv_path(&key, &master, info->path));

      btc_hdpub_get_str(str1, &key, btc_mainnet);
      btc_hdpriv_get_str(str2, &key, btc_mainnet);

      ASSERT(strcmp(str1, info->pub) == 0);
      ASSERT(strcmp(str2, info->prv) == 0);

      ASSERT(btc_hdpub_equal(&key, &pub));
      ASSERT(btc_hdpriv_equal(&key, &prv));
    }
  }
}

static void
test_derive(void) {
  btc_hdnode_t pub, prv;
  btc_hdnode_t master;

  btc_hdpriv_generate(&master, BTC_BIP32_STANDARD);

  ASSERT(btc_hdpriv_path(&prv, &master, "m/1/2/3"));
  ASSERT(btc_hdpub_path(&pub, &master, "m/1/2/3"));

  ASSERT(!btc_hdpriv_equal(&prv, &master));
  ASSERT(!btc_hdpub_equal(&pub, &master));

  ASSERT(btc_hdpub_equal(&pub, &prv));
}

static void
test_bip44(void) {
  btc_hdnode_t master, account;
  btc_hdnode_t pub, prv;

  btc_hdpriv_generate(&master, BTC_BIP32_STANDARD);

  ASSERT(btc_hdpriv_account(&account, &master, 44, 0, 100)); /* Account 100 */
  ASSERT(btc_hdpriv_leaf(&prv, &account, 0, 7)); /* Receive Addr 7 */
  ASSERT(btc_hdpub_leaf(&pub, &account, 0, 7)); /* Receive Addr 7 */

  ASSERT(!btc_hdpriv_equal(&prv, &master));
  ASSERT(!btc_hdpub_equal(&pub, &master));

  ASSERT(!btc_hdpriv_equal(&prv, &account));
  ASSERT(!btc_hdpub_equal(&pub, &account));

  ASSERT(btc_hdpub_equal(&pub, &prv));
}

/*
 * Main
 */

int main(void) {
  test_vectors();
  test_derive();
  test_bip44();
  return 0;
}
