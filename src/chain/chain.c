int
btc_chain_add(btc_chain_t *chain, btc_block_t *block, int flags, int id) {
  btc_entry_t *prev, *entry;
  uint8_t hash[32];

  btc_header_hash(hash, &block->header);

  /* Special case for genesis block. */
  if (btc_hash_equal(hash, chain->network->genesis.hash)) {
    btc_chain_log(chain, "Saw genesis block: %h.\n", hash);
    chain->verify_error(chain->arg, hash, "duplicate", "duplicate", 0);
    return 0;
  }

  // If the block is already known to be
  // an orphan, ignore it.
  if (btc_chain_has_orphan(chain, hash)) {
    btc_chain_log(chain, "Already have orphan block: %h.\n", hash);
    chain->verify_error(chain->arg, hash, "duplicate", "duplicate", 0);
    return 0;
  }

  // Do not revalidate known invalid blocks.
  if (btc_chain_has_invalid(chain, hash)) {
    btc_chain_log(chain, "Invalid ancestors for block: %h.\n", hash);
    chain->verify_error(chain->arg, hash, "duplicate", "duplicate", 100);
    return 0;
  }

  // Check the POW before doing anything.
  if (flags & BTC_CHAIN_VERIFY_POW) {
    if (!btc_header_verify(&block->header)) {
      chain->verify_error(chain->arg, hash, "invalid", "high-hash", 50);
      return 0;
    }
  }

  // Do we already have this block?
  if (btc_chain_has_entry(chain, hash)) {
    btc_chain_log(chain, "Already have block: %h.\n", hash);
    chain->verify_error(chain->arg, hash, "duplicate", "duplicate", 0);
    return 0;
  }

  // Find the previous block entry.
  prev = btc_chain_get_entry(chain, block->header.prev_block);

  // If previous block wasn't ever seen,
  // add it current to orphans and return.
  if (prev == NULL) {
    btc_chain_store_orphan(chain, block, id);
    return 0;
  }

  // Connect the block.
  entry = btc_chain_connect(chain, prev, block, flags);

  if (entry == NULL)
    return 0;

  // Handle any orphans.
  if (btc_chain_has_next_orphan(chain, hash))
    btc_chain_handle_orphans(chain, entry);

  return 1;
}

static btc_entry_t *
btc_chain_connect(btc_chain_t *chain, btc_entry_t *prev, btc_block_t *block, int flags) {
  btc_entry_t *entry = btc_entry_create();

  btc_entry_set_block(entry, block, prev);

  entry->prev = prev;

  if (btc_hash_compare(entry->chainwork, chain->tip->chainwork) <= 0) {
    if (!btc_chain_save_alternate(chain, entry, block, prev, flags)) {
      btc_entry_destroy(entry);
      return NULL;
    }

    return entry;
  }

  if (!btc_chain_set_best_chain(chain, entry, block, prev, flags)) {
    btc_entry_destroy(entry);
    return NULL;
  }

  prev->next = entry;

  return entry;
}

static int
btc_chain_save_alternate(btc_chain_t *chain,
                         const btc_entry_t *entry,
                         btc_block_t *block,
                         const btc_entry_t *prev,
                         int flags) {
  int ret = 0;

  if (chain->checkpoints_enabled) {
    if (prev->height + 1 < chain->network->last_checkpoint) {
      chain->verify_error(chain->arg, entry->hash, "checkpoint",
                          "bad-fork-prior-to-checkpoint",
                          100);
      goto fail;
    }
  }

  if (!btc_chain_verify(chain, block, prev, flags)) {
    btc_chain_log(chain, "Invalid block on alternate chain: %h (%d).\n",
                         entry->hash, entry->height);
    goto fail;
  }

  CHECK(btc_chaindb_save(chain->db, entry, block, NULL));

  btc_chain_log(chain, "Heads up: Competing chain at height %d.\n");

  ret = 1;
fail:
  btc_block_destroy(block);
  return ret;
}

static int
btc_chain_set_best_chain(btc_chain_t *chain,
                         const btc_entry_t *entry,
                         btc_block_t *block,
                         const btc_entry_t *prev,
                         int flags) {
  const btc_entry_t *fork = NULL;
  btc_entry_t *tip = chain->tip;
  btc_deploy_state_t state;
  btc_view_t *view;
  int ret = 0;

  /* A higher fork has arrived. Time to reorganize the chain. */
  if (!btc_hash_equal(entry->header.prev_block, chain->tip->hash)) {
    /* Do as much verification as we can before reorganizing. */
    if (!btc_chain_verify(chain, block, prev, flags)) {
      btc_chain_log(chain, "Tried to connect invalid block: %h (%d).\n",
                           entry->hash, entry->height);
      goto fail;
    }

    btc_chain_log(chain, "WARNING: Reorganizing chain.\n");

    fork = btc_chain_reorganize(chain, entry);

    if (fork == NULL)
      goto fail;
  }

  /* Otherwise, everything is in order. Do "contextual" verification
     on our block now that we're certain its previous block is in
     the chain. */
  view = btc_chain_verify_context(chain, &state, block, prev, flags);

  if (view == NULL) {
    btc_chain_log(chain, "Tried to connect invalid block: %h (%d).\n",
                         entry->hash, entry->height);

    if (fork != NULL) {
      if (btc_hash_compare(chain->tip->chainwork, tip->chainwork) < 0)
        btc_chain_unreorganize(chain, fork, tip);
    }

    goto fail;
  }

  CHECK(btc_chaindb_save(chain->db, entry, block, view));

  chain->tip = entry;
  chain->height = entry->height;
  chain->state = state;

  chain->on_connect(chain->arg, entry, block, view);

  btc_view_destroy(view);

  ret = 1;
fail:
  btc_block_destroy(block);
  return ret;
}

static const btc_entry_t *
btc_chain_find_fork(btc_chain_t *chain,
                    const btc_entry_t *fork,
                    const btc_entry_t *longer) {
  while (fork != longer) {
    while (longer.height > fork.height) {
      longer = longer->prev;

      CHECK(longer != NULL);
    }

    if (fork == longer)
      return fork;

    fork = fork->prev;

    CHECK(fork != NULL);
  }

  return fork;
}

static const btc_entry_t *
btc_chain_reorganize(btc_chain_t *chain, const btc_entry_t *competitor) {
  const btc_entry_t *tip = chain->tip;
  const btc_entry_t *fork = btc_chain_find_fork(chain, competitor);
  btc_vector_t disconnect, connect;
  const btc_entry_t *entry;

  CHECK(fork != NULL);

  btc_vector_init(&disconnect);
  btc_vector_init(&connect);

  /* Blocks to disconnect. */
  for (entry = tip; entry != fork; entry = entry->prev) {
    btc_vector_push(&disconnect, entry);
    entry = entry->prev;
  }

  /* Blocks to connect. */
  for (entry = competitor; entry != fork; entry = entry->prev) {
    btc_vector_push(&connect, entry);
    entry = entry->prev;
  }

  for (i = 0; i < disconnect.length; i++) {
    entry = (const btc_entry_t *)disconnect.items[i];

    CHECK(btc_chain_disconnect(chain, entry));

    if (entry->prev != NULL)
      entry->prev->next = NULL;
  }

  CHECK(connect.length > 0);

  for (i = connect.length - 1; i != 0; i--) {
    entry = (const btc_entry_t *)connect.items[i];

    if (!btc_chain_reconnect(chain, entry)) {
      if (btc_hash_compare(chain->tip->chainwork, tip->chainwork) < 0)
        btc_chain_unreorganize(chain, fork, tip);

      fork = NULL;
      goto done;
    }

    if (entry->prev != NULL)
      entry->prev->next = entry;
  }

  chain->on_reorganize(arg, tip, competitor);

done:
  btc_vector_clear(&disconnect);
  btc_vector_clear(&connect);
  return fork;
}

static void
btc_chain_unreorganize(btc_chain_t *chain,
                       const btc_entry_t *fork,
                       const btc_entry_t *last) {
  const btc_entry_t *tip = chain->tip;
  btc_vector_t disconnect, connect;
  const btc_entry_t *entry;

  btc_vector_init(&disconnect);
  btc_vector_init(&connect);

  /* Blocks to disconnect. */
  for (entry = tip; entry != fork; entry = entry->prev) {
    btc_vector_push(&disconnect, entry);
    entry = entry->prev;
  }

  /* Blocks to connect. */
  for (entry = last; entry != fork; entry = entry->prev) {
    btc_vector_push(&connect, entry);
    entry = entry->prev;
  }

  for (i = 0; i < disconnect.length; i++) {
    entry = (const btc_entry_t *)disconnect.items[i];

    CHECK(btc_chain_disconnect(chain, entry));
  }

  for (i = connect.length - 1; i != (size_t)-1; i--) {
    entry = (const btc_entry_t *)connect.items[i];

    CHECK(btc_chain_reconnect(chain, entry));
  }

  chain->on_reorganize(arg, tip, last);

  btc_vector_clear(&disconnect);
  btc_vector_clear(&connect);
}

static int
btc_chain_reconnect(btc_chain_t *chain, const btc_entry_t *entry) {
  int flags = BTC_CHAIN_VERIFY_NONE;
  btc_deploy_state_t state;
  btc_entry_t *prev;
  btc_block_t *block;
  btc_view_t *view;
  int ret = 0;

  block = btc_chain_get_block(chain, entry->hash);

  if (block == NULL) {
    btc_chain_log(chain, "Block data not found: %h (%d).\n",
                         entry->hash, entry->height);

    return 0;
  }

  prev = entry->prev;

  CHECK(prev != NULL);

  view = btc_chain_verify_context(chain, &state, block, prev, flags);

  if (view == NULL) {
    btc_chain_log(chain, "Tried to connect invalid block: %h (%d).\n",
                         entry->hash, entry->height);
    goto fail;
  }

  CHECK(btc_chaindb_reconnect(chain->db, entry, block, view));

  chain->tip = entry;
  chain->height = entry->height;
  chain->state = state;

  chain->on_connect(chain->arg, entry, block, view);

  btc_view_destroy(view);

  ret = 1;
fail:
  btc_block_destroy(block);
  return ret;
}

static int
btc_chain_disconnect(btc_chain_t *chain, const btc_entry_t *entry) {
  btc_entry_t *prev;
  btc_block_t *block;
  btc_view_t *view;

  block = btc_chain_get_block(chain, entry->hash);

  if (block == NULL) {
    btc_chain_log(chain, "Block data not found: %h (%d).\n",
                         entry->hash, entry->height);

    return 0;
  }

  prev = entry->prev;

  CHECK(prev != NULL);

  view = btc_chaindb_disconnect(chain->db, entry, block);

  CHECK(view != NULL);

  chain->tip = entry;
  chain->height = entry->height;

  chain->on_disconnect(chain->arg, entry, block, view);

  btc_view_destroy(view);
  btc_block_destroy(block);

  return 1;
}

uint32_t
btc_chain_get_target(btc_chain_t *chain, uint32_t time, const btc_entry_t *prev) {
  const btc_network_t *net = chain->network;
  const btc_entry_t *first;
  int height;

  if (prev == NULL) {
    CHECK(time == net->genesis.header.time);
    return net->pow.bits;
  }

  /* Do not retarget. */
  if ((prev->height + 1) % net->pow.retarget_interval != 0) {
    if (net->pow.target_reset) {
      /* Special behavior for testnet. */
      if ((uint64_t)time > (uint64_t)prev->time + net->pow.target_spacing * 2)
        return net->pow.bits;
    }

    while (prev->prev != NULL
           && prev->height % net->pow.retarget_interval != 0
           && prev->header.bits == net->pow.bits) {
      prev = prev->prev;
    }

    return prev->bits;
  }

  /* Back 2 weeks. */
  height = (int)prev->height - ((int)net->pow.retarget_interval - 1);
  CHECK(height >= 0);

  first = btc_chain_get_ancestor(chain, prev, height);
  CHECK(first != NULL);

  return btc_chain_retarget(chain, prev, first);
}

static uint32_t
btc_chain_retarget(btc_chain_t *chain, const btc_entry_t *prev, const btc_entry_t *first) {
  const btc_network_t *net = chain->network;
  int64_t target_timespan = net->pow.target_timespan;
  int64_t actual_timespan;
  mpz_t limit, target;
  uint32_t ret;

  if (net->pow.no_retargeting)
    return prev->header.bits;

  mpz_init(limit);
  mpz_import(limit, net->pow.limit, 32, -1);

  mpz_init_set_compact(target, prev->header.bits);

  actual_timespan = (int64_t)prev->header.time - (int64_t)first->header.time;

  if (actual_timespan < target_timespan / 4)
    actual_timespan = target_timespan / 4;

  if (actual_timespan > target_timespan * 4)
    actual_timespan = target_timespan * 4;

  mpz_mul(target, target, actual_timespan);
  mpz_quo(target, target, target_timespan);

  if (mpz_cmp(target, limit) <= 0) {
    ret = mpz_get_compact(target);
  else
    ret = net->pow.bits;

  mpz_clear(limit);
  mpz_clear(target);

  return ret;
}
