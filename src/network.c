/*!
 * network.c - network functions for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/network.h>
#include "internal.h"

/*
 * Network
 */

const btc_checkpoint_t *
btc_network_checkpoint(const btc_network_t *network, int32_t height) {
  const btc_checkpoint_t *chk;
  size_t i;

  if (height > network->last_checkpoint)
    return NULL;

  for (i = 0; i < network->checkpoints.length; i++) {
    chk = &network->checkpoints.items[i];

    if (chk->height == height)
      return chk;
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
