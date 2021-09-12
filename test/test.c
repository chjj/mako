#undef NDEBUG

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <satoshi/coins.h>
#include <satoshi/script.h>
#include <satoshi/tx.h>
#include "data/sighash_vectors.h"
#include "data/script_vectors.h"
#include "data/tx_valid_vectors.h"
#include "data/tx_invalid_vectors.h"

#define lengthof(x) (sizeof(x) / sizeof((x)[0]))

static void
test_sighash_vector(const test_sighash_vector_t *vec, size_t index) {
  btc_script_t script;
  uint8_t msg[32];
  btc_tx_t tx;

  printf("sighash vector #%d: %s\n", (int)index, vec->comments);

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
test_script_vector(const test_script_vector_t *vec, size_t index) {
  btc_tx_t prev, tx;

  printf("script vector #%d: %s\n", (int)index, vec->comments);

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
test_tx_valid_vector(const test_valid_vector_t *vec, size_t index) {
  btc_coin_t *coin;
  btc_view_t *view;
  btc_tx_t tx;
  size_t i;

  printf("tx valid vector #%d: %s\n", (int)index, vec->comments);

  btc_tx_init(&tx);

  view = btc_view_create();

  assert(btc_tx_import(&tx, vec->tx_raw, vec->tx_len));

  for (i = 0; i < vec->coins_len; i++) {
    coin = btc_coin_create();

    assert(btc_output_import(&coin->output, vec->coins[i].output_raw,
                                            vec->coins[i].output_len));

    btc_view_put(view, &vec->coins[i].outpoint, coin);
  }

  if (strstr(vec->comments, "Coinbase") == vec->comments)
    assert(btc_tx_check_sanity(NULL, &tx));
  else
    assert(btc_tx_verify(&tx, view, vec->flags));

  btc_tx_clear(&tx);
  btc_view_destroy(view);
}

static void
test_tx_invalid_vector(const test_invalid_vector_t *vec, size_t index) {
  btc_coin_t *coin;
  btc_view_t *view;
  btc_tx_t tx;
  size_t i;

  printf("tx invalid vector #%d: %s\n", (int)index, vec->comments);

  btc_tx_init(&tx);

  view = btc_view_create();

  assert(btc_tx_import(&tx, vec->tx_raw, vec->tx_len));

  for (i = 0; i < vec->coins_len; i++) {
    coin = btc_coin_create();

    assert(btc_output_import(&coin->output, vec->coins[i].output_raw,
                                            vec->coins[i].output_len));

    btc_view_put(view, &vec->coins[i].outpoint, coin);
  }

  if (strcmp(vec->comments, "Duplicate inputs") == 0) {
    assert(btc_tx_verify(&tx, view, vec->flags));
    assert(!btc_tx_check_sanity(NULL, &tx));
  } else if (strcmp(vec->comments, "Negative output") == 0) {
    assert(btc_tx_verify(&tx, view, vec->flags));
    assert(!btc_tx_check_sanity(NULL, &tx));
  } else if (strstr(vec->comments, "Coinbase") == vec->comments) {
    assert(!btc_tx_check_sanity(NULL, &tx));
  } else {
    assert(!btc_tx_verify(&tx, view, vec->flags));
  }

  btc_tx_clear(&tx);
  btc_view_destroy(view);
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

static void
test_tx_valid(void) {
  size_t i;

  for (i = 0; i < lengthof(test_valid_vectors); i++)
    test_tx_valid_vector(&test_valid_vectors[i], i);
}

static void
test_tx_invalid(void) {
  size_t i;

  for (i = 0; i < lengthof(test_invalid_vectors); i++)
    test_tx_invalid_vector(&test_invalid_vectors[i], i);
}

int main(void) {
  test_sighash();
  test_script();
  test_tx_valid();
  test_tx_invalid();
  return 0;
}
