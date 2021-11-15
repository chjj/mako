/*!
 * t-bip39.c - bip39 test for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mako/bip32.h>
#include <mako/bip39.h>
#include <mako/encoding.h>
#include <mako/network.h>
#include <mako/util.h>
#include "lib/tests.h"
#include "data/bip39_vectors.h"

int main(void) {
  char phrase[BTC_PHRASE_MAX + 1];
  char xprv[BTC_BIP32_STRLEN + 1];
  uint8_t raw[BTC_MNEMONIC_SIZE];
  btc_mnemonic_t mn, orig;
  uint8_t entropy[64];
  uint8_t expect[64];
  uint8_t seed[64];
  btc_hdnode_t key;
  size_t i;

  btc_mnemonic_init(&mn);

  for (i = 0; i < lengthof(bip39_vectors); i++) {
    const struct bip39_vector *vector = &bip39_vectors[i];
    size_t len = sizeof(entropy);

    hex_decode(entropy, &len, vector->entropy);
    hex_parse(expect, 64, vector->seed);

    btc_mnemonic_set(&mn, entropy, len);

    btc_mnemonic_get_phrase(phrase, &mn);
    btc_mnemonic_seed(seed, &mn, vector->passphrase);

    ASSERT(strcmp(phrase, vector->phrase) == 0);
    ASSERT(memcmp(seed, expect, sizeof(expect)) == 0);

    ASSERT(btc_hdpriv_set_mnemonic(&key, 0, &mn, vector->passphrase));

    btc_hdpriv_get_str(xprv, &key, btc_mainnet);

    ASSERT(strcmp(xprv, vector->xprv) == 0);

    btc_mnemonic_copy(&orig, &mn);

    ASSERT(btc_mnemonic_equal(&mn, &orig));

    btc_mnemonic_clear(&mn);

    ASSERT(!btc_mnemonic_equal(&mn, &orig));

    ASSERT(btc_mnemonic_set_phrase(&mn, vector->phrase));
    ASSERT(btc_mnemonic_equal(&mn, &orig));

    len = btc_mnemonic_export(raw, &mn);

    btc_mnemonic_clear(&mn);

    ASSERT(btc_mnemonic_import(&mn, raw, len));
    ASSERT(btc_mnemonic_equal(&mn, &orig));
  }

  return 0;
}
