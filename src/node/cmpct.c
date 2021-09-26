/*!
 * cmpct.c - compact blocks for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <node/mempool.h>

#include <satoshi/bip152.h>
#include <satoshi/tx.h>

#include "../internal.h"

/*
 * Compact Block
 */

int
btc_cmpct_fill_mempool(btc_cmpct_t *blk, btc_mempool_t *mp, int witness) {
  size_t total = blk->ptx.length + blk->ids.length;
  struct kh_btc_idmap_s *set;
  const btc_mpentry_t *entry;
  btc_mpiter_t iter;
  uint8_t hash[32];
  uint64_t id;
  int index;

  if (blk->count == total)
    return 1;

  CHECK(blk->avail.length == total);

  set = btc_idmap_create();

  btc_mempool_iterate(&iter, mp);

  while (btc_mempool_next(&entry, &iter)) {
    if (witness) {
      btc_tx_wtxid(hash, &entry->tx);
      id = btc_cmpct_sid(blk, hash);
    } else {
      id = btc_cmpct_sid(blk, entry->hash);
    }

    index = btc_idmap_get(blk->id_map, id);

    if (index == -1)
      continue;

    CHECK((size_t)index < blk->avail.length);

    if (!btc_idmap_put(set, index, 0)) {
      /* Siphash collision, just request it. */
      btc_tx_destroy((btc_tx_t *)blk->avail.items[index]);
      blk->avail.items[index] = NULL;
      blk->count -= 1;
      continue;
    }

    blk->avail.items[index] = btc_tx_clone(&entry->tx);
    blk->count += 1;

    /* We actually may have a siphash collision
       here, but exit early anyway for perf. */
    if (blk->count == total) {
      btc_idmap_destroy(set);
      return 1;
    }
  }

  btc_idmap_destroy(set);

  return 0;
}
