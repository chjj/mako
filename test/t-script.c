/*!
 * t-script.c - script test for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <satoshi/coins.h>
#include <satoshi/script.h>
#include <satoshi/tx.h>
#include <satoshi/util.h>
#include "data/script_vectors.h"
#include "tests.h"

static void
test_script_vector(const test_script_vector_t *vec, size_t index) {
  btc_tx_t prev, tx;

  printf("script vector #%d: %s\n", (int)index, vec->comments);

  btc_tx_init(&prev);
  btc_tx_init(&tx);

  ASSERT(btc_tx_import(&prev, vec->prev_raw, vec->prev_len));
  ASSERT(btc_tx_import(&tx, vec->tx_raw, vec->tx_len));

  {
    const btc_script_t *input = &tx.inputs.items[0]->script;
    const btc_stack_t *witness = &tx.inputs.items[0]->witness;
    const btc_script_t *output = &prev.outputs.items[0]->script;
    int64_t value = prev.outputs.items[0]->value;
    unsigned int flags = vec->flags;
    btc_tx_cache_t cache;
    int ret;

    memset(&cache, 0, sizeof(cache));

    ret = btc_script_verify(input,
                            witness,
                            output,
                            &tx,
                            0,
                            value,
                            flags,
                            &cache);

    ASSERT(ret == vec->expected);
  }

  btc_tx_clear(&prev);
  btc_tx_clear(&tx);
}

int
main(void) {
  size_t i;

  for (i = 0; i < lengthof(test_script_vectors); i++)
    test_script_vector(&test_script_vectors[i], i);

  return 0;
}
