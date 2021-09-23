/*!
 * t-sighash.c - sighash test for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <satoshi/coins.h>
#include <satoshi/script.h>
#include <satoshi/tx.h>
#include <satoshi/util.h>
#include "data/sighash_vectors.h"
#include "lib/tests.h"

static void
test_sighash_vector(const test_sighash_vector_t *vec, size_t index) {
  btc_script_t script;
  uint8_t msg[32];
  btc_tx_t tx;

  printf("sighash vector #%d: %s\n", (int)index, vec->comments);

  btc_tx_init(&tx);
  btc_script_init(&script);

  ASSERT(btc_tx_import(&tx, vec->tx_raw, vec->tx_len));

  btc_script_set(&script, vec->script_raw, vec->script_len);

  btc_script_get_subscript(&script, &script, 0);
  btc_script_remove_separators(&script, &script);

  btc_tx_sighash(msg, &tx, vec->index, &script, 0, vec->type, 0, NULL);

  ASSERT(memcmp(msg, vec->expected, 32) == 0);

  btc_tx_clear(&tx);
  btc_script_clear(&script);
}

int
main(void) {
  size_t i;

  for (i = 0; i < lengthof(test_sighash_vectors); i++)
    test_sighash_vector(&test_sighash_vectors[i], i);

  return 0;
}
