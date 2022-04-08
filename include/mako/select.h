/*!
 * select.h - coin selector for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_SELECT_H
#define BTC_SELECT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "impl.h"
#include "types.h"

/*
 * Types
 */

enum btc_selection {
  BTC_SELECT_ALL,
  BTC_SELECT_RANDOM,
  BTC_SELECT_AGE,
  BTC_SELECT_VALUE
};

typedef struct btc_selopt_s {
  enum btc_selection strategy;
  int64_t rate;
  int64_t fee;
  int64_t maxfee;
  int32_t height;
  int32_t depth;
  int subfee;
  int subpos;
  int round;
  int smart;
} btc_selopt_t;

typedef struct btc_selector_s {
  const btc_selopt_t *opt;
  enum btc_selection strategy;
  int subtract;
  btc_tx_t *tx;
  int64_t inpval;
  int64_t outval;
  size_t size;
  btc_outset_t inputs;
  btc_vector_t utxos;
} btc_selector_t;

/*
 * Selector Options
 */

BTC_EXTERN void
btc_selopt_init(btc_selopt_t *opt);

/*
 * Selector
 */

BTC_EXTERN void
btc_selector_init(btc_selector_t *sel, const btc_selopt_t *opt, btc_tx_t *tx);

BTC_EXTERN void
btc_selector_clear(btc_selector_t *sel);

BTC_EXTERN void
btc_selector_push(btc_selector_t *sel,
                  const btc_outpoint_t *prevout,
                  const btc_coin_t *coin);

BTC_EXTERN int
btc_selector_fill(btc_selector_t *sel, const btc_address_t *addr);

#ifdef __cplusplus
}
#endif

#endif /* BTC_SELECT_H */
