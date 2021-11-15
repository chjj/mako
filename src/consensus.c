/*!
 * consensus.c - consensus functions for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stddef.h>
#include <stdint.h>
#include <mako/consensus.h>
#include "internal.h"

/*
 * Consensus
 */

int
btc_has_versionbit(uint32_t version, int bit) {
  if ((version & BTC_VERSION_TOP_MASK) != BTC_VERSION_TOP_BITS)
    return 0;

  return (version >> bit) & 1;
}

int64_t
btc_get_reward(int32_t height, int32_t interval) {
  int64_t subsidy = BTC_BASE_REWARD;
  int32_t halvings = height / interval;

  if (halvings >= 64)
    return 0;

  return subsidy >> halvings;
}
