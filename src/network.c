/*!
 * network.c - network functions for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <mako/network.h>
#include "internal.h"

/*
 * Network
 */

const btc_checkpoint_t *
btc_network_checkpoint(const btc_network_t *network, int32_t height) {
  const btc_checkpoint_t *chk;
  int start, end, pos;

  if (height > network->last_checkpoint)
    return NULL;

  start = 0;
  end = (int)network->checkpoints.length - 1;

  while (start <= end) {
    pos = (start + end) >> 1;
    chk = &network->checkpoints.items[pos];

    if (chk->height == height)
      return chk;

    if (chk->height < height)
      start = pos + 1;
    else
      end = pos - 1;
  }

  return NULL;
}

const btc_checkpoint_t *
btc_network_bip30(const btc_network_t *network, int32_t height) {
  const btc_checkpoint_t *chk;
  size_t i;

  for (i = 0; i < network->softforks.bip30.length; i++) {
    chk = &network->softforks.bip30.items[i];

    if (chk->height == height)
      return chk;
  }

  return NULL;
}

const btc_deployment_t *
btc_network_deployment(const btc_network_t *network, const char *name) {
  const btc_deployment_t *deploy;
  size_t i;

  for (i = 0; i < network->deployments.length; i++) {
    deploy = &network->deployments.items[i];

    if (strcmp(deploy->name, name) == 0)
      return deploy;
  }

  return NULL;
}
