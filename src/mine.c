/*!
 * mine.c - mine function for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/mine.h>
#include <torsion/hash.h>
#include "impl.h"
#include "internal.h"

/*
 * Mining / PoW
 */

int
btc_mine(btc_header_t *hdr,
         const uint8_t *target,
         uint64_t limit,
         uint32_t (*adjtime)(void *),
         void *arg) {
  uint64_t attempt = 0;
  hash256_t pre, ctx;
  uint8_t hash[32];

  memset(&pre, 0, sizeof(pre));

  for (;;) {
    hdr->time = adjtime(arg);

    hash256_init(&pre);

    btc_uint32_update(&pre, hdr->version);
    btc_raw_update(&pre, hdr->prev_block, 32);
    btc_raw_update(&pre, hdr->merkle_root, 32);
    btc_uint32_update(&pre, hdr->time);
    btc_uint32_update(&pre, hdr->bits);

    do {
      ctx = pre;

      btc_uint32_update(&ctx, hdr->nonce);

      hash256_final(&ctx, hash);

      if (btc_hash_compare(hash, target) <= 0)
        return 1;

      hdr->nonce++;

      if (limit > 0 && ++attempt == limit)
        return 0;
    } while (hdr->nonce != 0);
  }
}
