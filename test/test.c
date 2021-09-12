#undef NDEBUG

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <satoshi/script.h>
#include <satoshi/tx.h>
#include "data/sighash_vectors.h"
#include "data/script_vectors.h"

#define lengthof(x) (sizeof(x) / sizeof((x)[0]))

static void
test_sighash_vector(const test_sighash_vector_t *vec, size_t i) {
  btc_script_t script;
  uint8_t msg[32];
  btc_tx_t tx;

  printf("sighash vector #%d: %s\n", (int)i, vec->comments);

  btc_tx_init(&tx);
  btc_script_init(&script);

  assert(btc_tx_import(&tx, vec->tx_raw, vec->tx_len));

  btc_script_set(&script, vec->script_raw, vec->script_len);

  btc_script_get_subscript(&script, &script, 0);
  btc_script_remove_separators(&script, &script);

  btc_tx_sighash(msg, &tx, vec->index, &script, 0, vec->type, 0, NULL);

  assert(memcmp(msg, vec->expected, 32) == 0);

  btc_tx_clear(&tx);
  btc_script_clear(&script);
}

static void
test_script_vector(const test_script_vector_t *vec, size_t i) {
  btc_tx_t prev, tx;

  printf("script vector #%d: %s\n", (int)i, vec->comments);

  /* Import. */
  btc_tx_init(&prev);
  btc_tx_init(&tx);

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
test_sighash(void) {
  size_t i;

  for (i = 0; i < lengthof(test_sighash_vectors); i++)
    test_sighash_vector(&test_sighash_vectors[i], i);
}

static void
test_script(void) {
  size_t i;

  for (i = 0; i < lengthof(test_script_vectors); i++)
    test_script_vector(&test_script_vectors[i], i);
}

int main(void) {
  test_sighash();
  test_script();
  return 0;
}
