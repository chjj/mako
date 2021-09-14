
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

static btc_entry_t *
btc_chain_save_alternate(btc_chain_t *chain,
                         const btc_entry_t *entry,
                         btc_block_t *block,
                         const btc_entry_t *prev,
                         int flags) {
  int ret = 0;

  if (chain->checkpoints_enabled) {
    size_t index = chain->network->checkpoints.length - 1;
    const btc_checkpoint_t *last = &chain->network->checkpoints.items[index];

    if (prev->height + 1 < last->height) {
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

static btc_entry_t *
btc_chain_set_best_chain(btc_chain_t *chain,
                         const btc_entry_t *entry,
                         btc_block_t *block,
                         const btc_entry_t *prev,
                         int flags) {
  btc_entry_t *tip = chain->tip;
  btc_entry_t *fork = NULL;
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

static btc_entry_t *
btc_chain_find_fork(btc_chain_t *chain,
                    const btc_entry_t *fork,
                    const btc_entry_t *longer) {
  while (fork != longer) {
    while (longer.height > fork.height) {
      longer = longer->prev;

      if (longer == NULL)
        return NULL;
    }

    if (fork == longer)
      return fork;

    fork = fork->prev;

    if (fork == NULL)
      return NULL;
  }

  return fork;
}

static btc_entry_t *
btc_chain_reorganize(btc_chain_t *chain, const btc_entry_t *competitor) {
  btc_entry_t *tip = chain->tip;
  btc_entry_t *fork = btc_chain_find_fork(chain, competitor);
  btc_entryvec_t disconnect, connect;
  btc_entry_t *entry;

  CHECK(fork != NULL);

  btc_entryvec_init(&disconnect);
  btc_entryvec_init(&connect);

  /* Blocks to disconnect. */
  for (entry = tip; entry != fork; entry = entry->prev) {
    btc_entryvec_push(&disconnect, entry);
    entry = entry->prev;
  }

  /* Blocks to connect. */
  for (entry = competitor; entry != fork; entry = entry->prev) {
    btc_entryvec_push(&connect, entry);
    entry = entry->prev;
  }

  for (i = 0; i < disconnect.length; i++)
    CHECK(btc_chain_disconnect(chain, disconnect.items[i]));

  CHECK(connect.length > 0);

  for (i = connect.length - 1; i != 0; i--) {
    if (!btc_chain_reconnect(chain, connect.items[i])) {
      if (btc_hash_compare(chain->tip->chainwork, tip->chainwork) < 0)
        btc_chain_unreorganize(chain, fork, tip);

      fork = NULL;
      goto done;
    }
  }

  chain->on_reorganize(arg, tip, competitor);

done:
  btc_entryvec_clear(&disconnect);
  btc_entryvec_clear(&connect);
  return fork;
}

static void
btc_chain_unreorganize(btc_chain_t *chain,
                       const btc_entry_t *fork,
                       const btc_entry_t *last) {
  btc_entry_t *tip = chain->tip;
  btc_entryvec_t disconnect, connect;
  btc_entry_t *entry;

  btc_entryvec_init(&disconnect);
  btc_entryvec_init(&connect);

  /* Blocks to disconnect. */
  for (entry = tip; entry != fork; entry = entry->prev) {
    btc_entryvec_push(&disconnect, entry);
    entry = entry->prev;
  }

  /* Blocks to connect. */
  for (entry = last; entry != fork; entry = entry->prev) {
    btc_entryvec_push(&connect, entry);
    entry = entry->prev;
  }

  for (i = 0; i < disconnect.length; i++)
    CHECK(btc_chain_disconnect(chain, disconnect.items[i]));

  for (i = connect.length - 1; i != (size_t)-1; i--)
    CHECK(btc_chain_reconnect(chain, connect.items[i]));

  chain->on_reorganize(arg, tip, last);

  btc_entryvec_clear(&disconnect);
  btc_entryvec_clear(&connect);
}
