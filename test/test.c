#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <satoshi/script.h>
#include <satoshi/tx.h>
#include "data/script_vectors.h"

static void
test_script_vector(const script_vector_t *vec) {
  btc_tx_t prev, tx;

  /* Import. */
  btc_tx_init(&prev);
  btc_tx_init(&tx);

  printf("Script test vector: %s\n", vec->comments);

  assert(btc_tx_import(&prev, vec->prev_raw, vec->prev_len));
  assert(btc_tx_import(&tx, vec->tx_raw, vec->tx_len));

  /* Test. */
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

    assert(ret == vec->expected);
  }

  /* Clear. */
  btc_tx_clear(&prev);
  btc_tx_clear(&tx);
}

static void
test_script(void) {
  size_t i;

  for (i = 0; i < sizeof(script_vectors) / sizeof(script_vectors[0]); i++)
    test_script_vector(&script_vectors[i]);
}

int main(void) {
  test_script();
  return 0;
}
