/*!
 * select.c - coin selector for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <mako/address.h>
#include <mako/coins.h>
#include <mako/consensus.h>
#include <mako/crypto/rand.h>
#include <mako/heap.h>
#include <mako/map.h>
#include <mako/policy.h>
#include <mako/script.h>
#include <mako/select.h>
#include <mako/tx.h>
#include <mako/util.h>
#include <mako/vector.h>

#include "impl.h"
#include "internal.h"

/*
 * Types
 */

typedef struct btc_utxo_s {
  btc_outpoint_t prevout;
  int32_t height;
  int64_t value;
  size_t size;
} btc_utxo_t;

/*
 * Helpers
 */

static size_t
estimate_input_size(const btc_script_t *prev) {
  size_t base = 40;
  size_t wit = 0;
  unsigned int m;
  size_t weight;

  if (btc_script_is_p2pk(prev)) {
    /* P2PK */
    /* varint script size */
    base += 1;
    /* OP_PUSHDATA0 [signature] */
    base += 1 + 73;
  } else if (btc_script_is_p2pkh(prev)) {
    /* P2PKH */
    /* varint script size */
    base += 1;
    /* OP_PUSHDATA0 [signature] */
    base += 1 + 73;
    /* OP_PUSHDATA0 [key] */
    base += 1 + 33;
  } else if (btc_script_get_multisig(&m, NULL, NULL, prev)) {
    /* Bare Multisig */
    /* varint len */
    base += 3;
    /* OP_0 */
    base += 1;
    /* OP_PUSHDATA0 [signature] ... */
    base += (1 + 73) * m;
  } else if (btc_script_is_p2sh(prev)) {
    /* Nested P2WPKH */
    /* varint-items-len */
    wit += 1;
    /* varint-len [signature] */
    wit += 1 + 73;
    /* varint-len [key] */
    wit += 1 + 33;
    /* varint script size */
    base += 1;
    /* OP_PUSHDATA0 [redeem] */
    base += 1 + 22;
  } else if (btc_script_is_p2wpkh(prev)) {
    /* P2WPKH */
    /* varint-items-len */
    wit += 1;
    /* varint-len [signature] */
    wit += 1 + 73;
    /* varint-len [key] */
    wit += 1 + 33;
  } else if (btc_script_is_p2wsh(prev)) {
    /* P2WSH */
    /* varint-items-len */
    wit += 1;
    /* 2-of-3 multisig input */
    wit += 149;
  } else if (btc_script_is_program(prev)) {
    /* Unknown witness program. */
    wit += 110;
  } else {
    /* Unknown. */
    base += 110;
  }

  weight = (base * BTC_WITNESS_SCALE_FACTOR) + wit;

  return (weight + BTC_WITNESS_SCALE_FACTOR - 1) / BTC_WITNESS_SCALE_FACTOR;
}

static int64_t
dust_threshold(const btc_output_t *output) {
  return btc_output_dust_threshold(output, BTC_MIN_RELAY);
}

static int
subtract_pos(btc_tx_t *tx, size_t index, int64_t fee) {
  btc_output_t *output;

  if (index >= tx->outputs.length)
    return 0;

  output = tx->outputs.items[index];

  if (output->value < fee + dust_threshold(output))
    return 0;

  output->value -= fee;

  return 1;
}

static int
subtract_fee(btc_tx_t *tx, int64_t fee) {
  int64_t outputs = 0;
  int64_t share, left;
  size_t i;

  for (i = 0; i < tx->outputs.length; i++) {
    btc_output_t *output = tx->outputs.items[i];

    /* Ignore nulldatas and other OP_RETURN scripts. */
    if (btc_script_is_unspendable(&output->script))
      continue;

    outputs += 1;
  }

  if (outputs == 0)
    return 0;

  share = fee / outputs;
  left = fee % outputs;

  /* First pass: remove even shares. */
  for (i = 0; i < tx->outputs.length; i++) {
    btc_output_t *output = tx->outputs.items[i];

    if (btc_script_is_unspendable(&output->script))
      continue;

    if (output->value < share + dust_threshold(output))
      return 0;

    output->value -= share;
  }

  /* Second pass: remove the remainder for the one unlucky output. */
  for (i = 0; i < tx->outputs.length; i++) {
    btc_output_t *output = tx->outputs.items[i];

    if (btc_script_is_unspendable(&output->script))
      continue;

    if (output->value >= left + dust_threshold(output)) {
      output->value -= left;
      return 1;
    }
  }

  return 0;
}

static int64_t
clamp_fee(int64_t fee) {
  if (fee < 1000)
    return 1000;

  if (fee > BTC_COIN / 10)
    return BTC_COIN / 10;

  return fee;
}

static int
cmp_oldest(const void *xp, const void *yp) {
  const btc_utxo_t *x = xp;
  const btc_utxo_t *y = yp;

  return BTC_CMP((uint32_t)x->height,
                 (uint32_t)y->height);
}

static int
cmp_newest(const void *xp, const void *yp) {
  return cmp_oldest(yp, xp);
}

static int
cmp_lowest(const void *xp, const void *yp) {
  const btc_utxo_t *x = xp;
  const btc_utxo_t *y = yp;
  int xh = (x->height < 0);
  int yh = (y->height < 0);

  if (xh != yh)
    return xh - yh;

  return BTC_CMP(x->value, y->value);
}

static int
cmp_highest(const void *xp, const void *yp) {
  const btc_utxo_t *x = xp;
  const btc_utxo_t *y = yp;
  int xh = (x->height < 0);
  int yh = (y->height < 0);

  if (xh != yh)
    return xh - yh;

  return BTC_CMP(y->value, x->value);
}

/*
 * Selector Options
 */

void
btc_selopt_init(btc_selopt_t *opt) {
  opt->strategy = BTC_SELECT_HIGHEST;
  opt->rate = 10000;
  opt->fee = -1;
  opt->maxfee = -1;
  opt->height = -1;
  opt->depth = -1;
  opt->subfee = 0;
  opt->subpos = -1;
  opt->round = 0;
  opt->smart = 0;
  opt->watch = 0;
}

/*
 * Selector
 */

void
btc_selector_init(btc_selector_t *sel, const btc_selopt_t *opt, btc_tx_t *tx) {
  size_t i;

  sel->opt = opt;
  sel->strategy = opt->strategy;
  sel->subtract = (opt->subfee || opt->subpos >= 0);
  sel->tx = tx;
  sel->inpval = 0;
  sel->outval = btc_tx_output_value(tx);
  sel->size = 12 + btc_outvec_size(&tx->outputs) + 34;
  sel->resolved = 0;
  sel->next = NULL;
  sel->state = NULL;

  btc_outset_init(&sel->inputs);
  btc_vector_init(&sel->utxos);

  for (i = 0; i < tx->inputs.length; i++) {
    btc_input_t *input = tx->inputs.items[i];

    CHECK(btc_outset_put(&sel->inputs, &input->prevout));
  }
}

void
btc_selector_clear(btc_selector_t *sel) {
  size_t i;

  btc_outset_clear(&sel->inputs);

  for (i = 0; i < sel->utxos.length; i++)
    btc_free(sel->utxos.items[i]);

  btc_vector_clear(&sel->utxos);
}

static int
btc_selector_spendable(const btc_selector_t *sel, const btc_coin_t *coin) {
  const btc_selopt_t *opt = sel->opt;

  if (coin->spent)
    return 0;

  if (opt->smart && !coin->safe) {
    if (coin->height == -1)
      return 0;
  }

  if (!opt->watch && coin->watch)
    return 0;

  if (opt->height >= 0 && coin->coinbase) {
    if (coin->height == -1)
      return 0; /* LCOV_EXCL_LINE */

    if (opt->height + 1 < coin->height + BTC_COINBASE_MATURITY + 20)
      return 0;
  }

  if (opt->depth >= 0 && opt->height >= 0) {
    int32_t depth = 0;

    if (coin->height >= 0 && opt->height >= coin->height)
      depth = opt->height - coin->height + 1;

    if (depth < opt->depth)
      return 0;
  }

  return 1;
}

int
btc_selector_push(btc_selector_t *sel,
                  const btc_outpoint_t *prevout,
                  const btc_coin_t *coin) {
  btc_utxo_t *utxo;

  if (btc_outset_has(&sel->inputs, prevout)) {
    sel->inpval += coin->output.value;
    sel->size += estimate_input_size(&coin->output.script);
    sel->resolved++;
    return 1;
  }

  if (!btc_selector_spendable(sel, coin))
    return 0;

  utxo = btc_malloc(sizeof(btc_utxo_t));

  utxo->prevout = *prevout;
  utxo->height = coin->height;
  utxo->value = coin->output.value;
  utxo->size = estimate_input_size(&coin->output.script);

  switch (sel->strategy) {
    case BTC_SELECT_ALL: {
      btc_vector_push(&sel->utxos, utxo);
      break;
    }

    case BTC_SELECT_RANDOM: {
      if (sel->utxos.length > 1) {
        size_t i = btc_uniform(sel->utxos.length);
        btc_utxo_t *tmp = sel->utxos.items[i];

        sel->utxos.items[i] = utxo;

        btc_vector_push(&sel->utxos, tmp);
      } else {
        btc_vector_push(&sel->utxos, utxo);
      }

      break;
    }

    case BTC_SELECT_OLDEST: {
      btc_heap_insert(&sel->utxos, utxo, cmp_oldest);
      break;
    }

    case BTC_SELECT_NEWEST: {
      btc_heap_insert(&sel->utxos, utxo, cmp_newest);
      break;
    }

    case BTC_SELECT_LOWEST: {
      btc_heap_insert(&sel->utxos, utxo, cmp_lowest);
      break;
    }

    case BTC_SELECT_HIGHEST: {
      btc_heap_insert(&sel->utxos, utxo, cmp_highest);
      break;
    }

    default: {
      btc_abort(); /* LCOV_EXCL_LINE */
      break;
    }
  }

  return 1;
}

static btc_utxo_t *
btc_selector_shift(btc_selector_t *sel) {
  switch (sel->strategy) {
    case BTC_SELECT_ALL:
    case BTC_SELECT_RANDOM:
      return btc_vector_pop(&sel->utxos);
    case BTC_SELECT_OLDEST:
      return btc_heap_shift(&sel->utxos, cmp_oldest);
    case BTC_SELECT_NEWEST:
      return btc_heap_shift(&sel->utxos, cmp_newest);
    case BTC_SELECT_LOWEST:
      return btc_heap_shift(&sel->utxos, cmp_lowest);
    case BTC_SELECT_HIGHEST:
      return btc_heap_shift(&sel->utxos, cmp_highest);
  }
  btc_abort(); /* LCOV_EXCL_LINE */
  return NULL; /* LCOV_EXCL_LINE */
}

static int64_t
btc_selector_total(const btc_selector_t *sel, int64_t fee) {
  if (sel->subtract)
    return sel->outval;

  return sel->outval + fee;
}

static int
btc_selector_full(const btc_selector_t *sel, int64_t fee) {
  return sel->inpval >= btc_selector_total(sel, fee);
}

static int64_t
btc_selector_fee(const btc_selector_t *sel, int64_t rate) {
  int64_t fee;

  if (sel->opt->round)
    fee = btc_round_fee(rate, sel->size);
  else
    fee = btc_get_fee(rate, sel->size);

  return clamp_fee(fee);
}

static int
btc_selector_should_fund(const btc_selector_t *sel, int64_t fee) {
  if (sel->utxos.length == 0)
    return 0;

  if (sel->strategy == BTC_SELECT_ALL)
    return 1;

  if (!btc_selector_full(sel, fee))
    return 1;

  return 0;
}

static void
btc_selector_next(btc_selector_t *sel) {
  btc_outpoint_t prevout;
  btc_coin_t *coin;
  int ok = 0;

  if (sel->next == NULL || sel->utxos.length > 0)
    return;

  while (ok == 0 && sel->next(sel, &prevout, &coin)) {
    ok = !btc_outset_has(&sel->inputs, &prevout);

    if (ok)
      ok = btc_selector_push(sel, &prevout, coin);

    btc_coin_destroy(coin);
  }
}

static void
btc_selector_fund(btc_selector_t *sel, int64_t fee) {
  btc_selector_next(sel);

  while (btc_selector_should_fund(sel, fee)) {
    btc_utxo_t *utxo = btc_selector_shift(sel);

    btc_tx_add_outpoint(sel->tx, &utxo->prevout);

    sel->inpval += utxo->value;
    sel->size += utxo->size;

    btc_free(utxo);

    btc_selector_next(sel);
  }
}

static int64_t
btc_selector_by_rate(btc_selector_t *sel, int64_t rate) {
  const btc_selopt_t *opt = sel->opt;
  int64_t fee;

  if (sel->strategy == BTC_SELECT_ALL) {
    btc_selector_fund(sel, 0);
  } else {
    btc_selector_next(sel);

    while (sel->utxos.length > 0) {
      fee = btc_selector_fee(sel, rate);

      if (btc_selector_full(sel, fee))
        break;

      btc_selector_fund(sel, fee);
    }
  }

  fee = btc_selector_fee(sel, rate);

  if (!btc_selector_full(sel, fee))
    return -1;

  if (opt->maxfee > 0 && fee > opt->maxfee)
    return -1;

  return sel->inpval - btc_selector_total(sel, fee);
}

static int64_t
btc_selector_by_fee(btc_selector_t *sel, int64_t fee) {
  btc_selector_fund(sel, fee);

  if (!btc_selector_full(sel, fee))
    return -1;

  return sel->inpval - btc_selector_total(sel, fee);
}

int
btc_selector_fill(btc_selector_t *sel, const btc_address_t *addr) {
  const btc_selopt_t *opt = sel->opt;
  btc_tx_t *tx = sel->tx;
  btc_output_t *output;
  int64_t change = -1;
  int64_t fee = 0;

  /* Ensure there are no unresolved inputs. */
  if (sel->resolved != sel->inputs.size)
    return 0;

  /* Select necessary coins. */
  if (opt->fee >= 0) {
    fee = clamp_fee(opt->fee);
    change = btc_selector_by_fee(sel, fee);
  } else if (opt->rate > 0) {
    change = btc_selector_by_rate(sel, opt->rate);
    fee = btc_selector_fee(sel, opt->rate);
  }

  if (change < 0) {
    /* Failed to find enough funds. */
    return 0;
  }

  /* Attempt to subtract fee. */
  if (opt->subfee) {
    if (!subtract_fee(tx, fee))
      return 0;
  } else if (opt->subpos >= 0) {
    if (!subtract_pos(tx, opt->subpos, fee))
      return 0;
  }

  /* Add a change output. */
  output = btc_output_create();
  output->value = change;

  btc_address_get_script(&output->script, addr);

  if (btc_output_is_dust(output, BTC_MIN_RELAY)) {
    /* Do nothing. Change is added to fee. */
    btc_output_destroy(output);
  } else {
    btc_outvec_push(&tx->outputs, output);
  }

  return 1;
}
