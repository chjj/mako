enum btc_chain_flags {
  BTC_CHAIN_VERIFY_NONE = 0,
  BTC_CHAIN_VERIFY_POW  = 1 << 0,
  BTC_CHAIN_VERIFY_BODY = 1 << 1,
  BTC_CHAIN_DEFAULT_FLAGS = BTC_CHAIN_VERIFY_POW | BTC_CHAIN_VERIFY_BODY
};

enum btc_lock_flags {
  BTC_CHAIN_VERIFY_SEQUENCE  = 1 << 0,
  BTC_CHAIN_MEDIAN_TIME_PAST = 1 << 1,
  BTC_CHAIN_MANDATORY_LOCKTIME_FLAGS = 0,
  BTC_CHAIN_STANDARD_LOCKTIME_FLAGS = BTC_CHAIN_VERIFY_SEQUENCE
                                    | BTC_CHAIN_MEDIAN_TIME_PAST
};

enum btc_threshold_state {
  BTC_CHAIN_DEFINED,
  BTC_CHAIN_STARTED,
  BTC_CHAIN_LOCKED_IN,
  BTC_CHAIN_ACTIVE,
  BTC_CHAIN_FAILED
};

typedef struct btc_dstate_s {
  unsigned int flags;
  unsigned int lock_flags;
  int bip34;
  int bip91;
  int bip148;
} btc_dstate_t;

static void
btc_dstate_init(btc_dstate_t *state) {
  state->flags = BTC_SCRIPT_MANDATORY_VERIFY_FLAGS;
  state->flags &= ~BTC_SCRIPT_VERIFY_P2SH;
  state->lock_flags = BTC_CHAIN_MANDATORY_LOCKTIME_FLAGS;
  state->bip34 = 0;
  state->bip91 = 0;
  state->bip148 = 0;
}

static int
btc_consensus_has_bit(uint32_t version, int bit) {
  if ((version & BTC_VERSION_TOP_MASK) != BTC_VERSION_TOP_BITS)
    return 0;

  return (version >> bit) & 1;
}

static int64_t
btc_consensus_get_reward(int32_t height, int32_t interval) {
  int64_t subsidy = BTC_BASE_REWARD;
  int32_t halvings = height / interval;

  if (halvings >= 64)
    return 0;

  return subsidy >> halvings;
}

static const btc_deployment_t *
btc_network_deployment(const btc_network_t *network, const char *name) {
  const btc_deployment_t *deploy;
  size_t i;

  for (i = 0; i < network->deployments.length; i++) {
    deploy = network->deployments.items[i];

    if (strcmp(deploy->name, name) == 0)
      return deploy;
  }

  return NULL;
}

static const btc_checkpoint_t *
btc_network_checkpoint(const btc_network_t *network, int32_t height) {
  const btc_checkpoint_t *chk;
  size_t i;

  if (height > network->last_checkpoint)
    return NULL;

  for (i = 0; i < network->checkpoints.length; i++) {
    chk = network->checkpoints.items[i];

    if (chk->height == height)
      return chk;
  }

  return NULL;
}

static const btc_checkpoint_t *
btc_network_bip30(const btc_network_t *network, int32_t height) {
  const btc_checkpoint_t *chk;
  size_t i;

  for (i = 0; i < network->softforks.bip30.length; i++) {
    chk = network->softforks.bip30.items[i];

    if (chk->height == height)
      return chk;
  }

  return NULL;
}







static int
btc_chain_throw(btc_chain_t *chain,
                const btc_header_t *header,
                const char *code,
                const char *reason,
                int score,
                int malleated) {
  btc_header_hash(chain->error.hash, header);

  chain->error.code = code;
  chain->error.reason = reason;
  chain->error.score = score;
  chain->error.malleated = malleated;

  printf("Chain error: code=%s reason=%s score=%d malleated=%d\n",
         code, reason, score, malleated);

  return 0;
}

const btc_verify_error_t *
btc_chain_error(btc_chain_t *chain) {
  return &chain->error;
}


static btc_entry_t *
btc_chain_get_ancestor(btc_chain_t *chain, btc_entry_t *entry, int32_t height) {
  CHECK(height >= 0);
  CHECK(height <= entry->height);

  if (btc_chaindb_is_main(chain->db, entry))
    return btc_chaindb_by_height(chain->db, height);

  while (entry->height != height)
    entry = entry->prev;

  return entry;
}

static int
btc_chain_is_active(btc_chain_t *chain,
                    btc_entry_t *prev,
                    const btc_deployment_t *deployment) {
  return btc_chain_get_state(chain, prev, deployment) == BTC_CHAIN_ACTIVE;
}

static int
btc_chain_get_state(btc_chain_t *chain,
                    btc_entry_t *prev,
                    const btc_deployment_t *deployment) {
  int32_t window = chain->network->miner_window;
  int32_t threshold = chain->network->activation_threshold;
  btc_entry_t *entry, *block;
  int bit = deployment->bit;
  btc_vector_t compute;
  int32_t height, count;
  int64_t time;
  int i, state;

  if (deployment->threshold != -1)
    threshold = deployment->threshold;

  if (deployment->window != -1)
    window = deployment->window;

  if (((prev->height + 1) % window) != 0) {
    height = prev->height - ((prev->height + 1) % window);
    prev = btc_chain_get_ancestor(chain, prev, height);

    if (prev == NULL)
      return BTC_CHAIN_DEFINED;

    CHECK(prev->height == height);
    CHECK(((prev->height + 1) % window) == 0);
  }

  entry = prev;
  state = BTC_CHAIN_DEFINED;

  btc_vector_init(&compute);

  while (entry != NULL) {
    time = btc_entry_median_time(entry);

    if (time < deployment->start_time) {
      state = BTC_CHAIN_DEFINED;
      break;
    }

    btc_vector_push(&compute, entry);

    height = entry.height - window;

    entry = btc_chain_get_ancestor(chain, entry, height);
  }

  while (compute.length > 0) {
    entry = (btc_entry_t *)btc_vector_pop(&compute);

    switch (state) {
      case BTC_CHAIN_DEFINED: {
        time = btc_entry_median_time(entry);

        if (time >= deployment->timeout) {
          state = BTC_CHAIN_FAILED;
          break;
        }

        if (time >= deployment->start_time) {
          state = BTC_CHAIN_STARTED;
          break;
        }

        break;
      }

      case BTC_CHAIN_STARTED: {
        time = btc_entry_median_time(entry);

        if (time >= deployment->timeout) {
          state = BTC_CHAIN_FAILED;
          break;
        }

        block = entry;
        count = 0;

        for (i = 0; i < window; i++) {
          if (btc_consensus_has_bit(block->header.version, bit))
            count++;

          if (count >= threshold) {
            state = BTC_CHAIN_LOCKED_IN;
            break;
          }

          block = block->prev;

          CHECK(block != NULL);
        }

        break;
      }

      case BTC_CHAIN_LOCKED_IN: {
        state = BTC_CHAIN_ACTIVE;
        break;
      }

      case BTC_CHAIN_FAILED:
      case BTC_CHAIN_ACTIVE: {
        break;
      }

      default: {
        btc_abort(); /* LCOV_EXCL_LINE */
        break;
      }
    }
  }

  btc_vector_clear(&compute);

  return state;
}

static void
btc_chain_get_deployments(btc_chain_t *chain,
                          btc_dstate_t *state,
                          int64_t time,
                          btc_entry_t *prev) {
  const btc_network_t *network = chain->network;
  int32_t height = prev.height + 1;
  const btc_deployment_t *deploy;
  int witness;

  btc_dstate_init(state);

  /* For some reason bitcoind has p2sh in the
   * mandatory flags by default, when in reality
   * it wasn't activated until march 30th 2012.
   * The first p2sh output and redeem script
   * appeared on march 7th 2012, only it did
   * not have a signature.
   *
   * See: 6a26d2ecb67f27d1fa5524763b49029d7106e91e3cc05743073461a719776192
   *      9c08a4d78931342b37fd5f72900fb9983087e6f46c4a097d8a1f52c74e28eaf6
   */
  if (time >= BTC_BIP16_TIME)
    state->flags |= BTC_SCRIPT_VERIFY_P2SH;

  /* Coinbase heights are now enforced (bip34). */
  if (height >= network->softfork.bip34.height)
    state->bip34 = 1;

  /* Signature validation is now enforced (bip66). */
  if (height >= network->softforks.bip66.height)
    state->flags |= BTC_SCRIPT_VERIFY_DERSIG;

  /* CHECKLOCKTIMEVERIFY is now usable (bip65). */
  if (height >= network->softforks.bip65.height)
    state->flags |= BTC_SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;

  /* CHECKSEQUENCEVERIFY and median time
     past locktimes are now usable (bip9 & bip113). */
  deploy = btc_network_deployment(network, "csv");

  if (btc_chain_is_active(chain, prev, deploy)) {
    state->flags |= BTC_SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    state->lock_flags |= BTC_CHAIN_VERIFY_SEQUENCE;
    state->lock_flags |= BTC_CHAIN_MEDIAN_TIME_PAST;
  }

  /* Check the state of the segwit deployment. */
  deploy = btc_network_deployment(network, "segwit");
  witness = btc_chain_get_state(chain, prev, deploy);

  /* Segregrated witness (bip141) is now usable. */
  // along with SCRIPT_VERIFY_NULLDUMMY (bip147).
  if (witness == BTC_CHAIN_ACTIVE) {
    state->flags |= BTC_SCRIPT_VERIFY_WITNESS;
    state->flags |= BTC_SCRIPT_VERIFY_NULLDUMMY;
  }

  /* Segsignal is now enforced (bip91). */
  if (chain->bip91_enabled) {
    if (witness == BTC_CHAIN_STARTED) {
      deploy = btc_network_deployment(network, "segsignal");

      if (btc_chain_is_active(chain, prev, deploy))
        state->bip91 = 1;
    }
  }

  /* UASF is now enforced (bip148) (mainnet-only). */
  if (chain->bip148_enabled && network->type == BTC_NETWORK_MAINNET) {
    if (witness != BTC_CHAIN_LOCKED_IN && witness != BTC_CHAIN_ACTIVE) {
      /* The BIP148 MTP check is nonsensical in
         that it includes the _current_ entry's
         timestamp. This requires some hackery,
         since we only operate on the sane
         assumption that deployment checks should
         only ever examine the values of the
         previous block (necessary for mining). */
      int64_t mtp = btc_entry_bip148_time(prev, time);

      if (mtp >= 1501545600 && mtp <= 1510704000)
        state->bip148 = 1;
    }
  }

  return state;
}

static int
btc_chain_is_historical(btc_chain_t *chain, const btc_entry_t *prev) {
  if (chain->checkpoints_enabled) {
    if (prev->height + 1 <= chain->network->last_checkpoint)
      return 1;
  }

  return 0;
}

static int
btc_chain_verify_checkpoint(btc_chain_t *chain,
                            const btc_entry_t *prev,
                            const uint8_t *hash) {
  const btc_network_t *network = chain->network;
  int32_t height = prev->height + 1;
  const btc_checkpoint_t *chk;
  size_t i;

  if (!chain->checkpoints_enabled)
    return 1;

  chk = btc_network_checkpoint(network, height);

  if (chk == NULL)
    return 1;

  if (btc_hash_equal(hash, chk->hash)) {
    btc_chain_log(chain, "Hit checkpoint block %h (%d).", hash, height);
    return 1;
  }

  /* Someone is either mining on top of
     an old block for no reason, or the
     consensus protocol is broken and
     there was a 20k+ block reorg. */
  btc_chain_log(chain,
    "Checkpoint mismatch at height %d: expected=%h received=%h",
    height,
    chk->hash,
    hash
  );

  btc_chain_purge_orphans(chain);

  return 0;
}

static int
btc_chain_verify(btc_chain_t *chain,
                 btc_dstate_t *state,
                 const btc_block_t *block,
                 const btc_entry_t *prev,
                 unsigned int flags) {
  const btc_header_t *hdr = &block->header;
  const btc_network_t *network = chain->network;
  uint8_t hash[32];
  uint8_t root[32];
  int64_t time, mtp;
  int32_t height;
  int has_commit;
  uint32_t bits;
  size_t i;

  btc_dstate_init(state);

  /* Extra sanity check. */
  if (!btc_hash_equal(block->header.prev_block, prev->hash))
    return btc_chain_throw(chain, hdr, "invalid", "bad-prevblk", 0, 0);

  /* Verify a checkpoint if there is one. */
  btc_header_hash(hash, &block->header);

  if (!btc_chain_verify_checkpoint(chain, prev, hash)) {
    return btc_chain_throw(chain, hdr,
                           "checkpoint",
                           "checkpoint mismatch",
                           100,
                           0);
  }

  /* Skip everything when using checkpoints.
     We can do this safely because every
     block in between each checkpoint was
     validated outside in the header chain. */
  if (btc_chain_is_historical(chain, prev)) {
    /* Check merkle root. */
    if (flags & BTC_CHAIN_VERIFY_BODY) {
      int rc = btc_block_merkle_root(root, block);

      if (rc == 0 || !btc_hash_equal(block->header.merkle_root, root)) {
        return btc_chain_throw(chain, hdr,
                               "invalid",
                               "bad-txnmrklroot",
                               100,
                               1);
      }

      flags &= ~BTC_CHAIN_VERIFY_BODY;
    }

    /* Once segwit is active, we will still
       need to check for block mutability. */
    if (!btc_block_has_witness(block)) {
      if (!btc_block_get_commitment_hash(root, block)) {
        btc_dstate_init(state);
        return 1;
      }
    }
  }

  /* Non-contextual checks. */
  if (flags & BTC_CHAIN_VERIFY_BODY) {
    btc_verify_error_t err;

    if (!btc_block_check_body(&err, block))
      return btc_chain_throw(chain, hdr, "invalid", err.reason, err.score, 1);
  }

  /* Ensure the POW is what we expect. */
  bits = btc_chain_get_target(chain, block->header.time, prev);

  if (block->bits != bits)
    return btc_chain_throw(chain, hdr, "invalid", "bad-diffbits", 100, 0);

  /* Ensure the timestamp is correct. */
  mtp = btc_entry_median_time(prev);

  if (block->header.time <= mtp)
    return btc_chain_throw(chain, hdr, "invalid", "time-too-old", 0, 0);

  /* Check timestamp against adjtime+2hours.
     If this fails we may be able to accept
     the block later. */
  if (block->time > btc_timedata_now(chain->time) + 2 * 60 * 60)
    return btc_chain_throw(chain, hdr, "invalid", "time-too-new", 0, 1);

  /* Calculate height of current block. */
  height = prev->height + 1;

  /* Only allow version 2 blocks (coinbase height)
     once the majority of blocks are using it. */
  if (block->header.version < 2 && height >= network->softforks.bip34.height)
    return btc_chain_throw(chain, hdr, "obsolete", "bad-version", 0, 0);

  /* Only allow version 3 blocks (sig validation)
     once the majority of blocks are using it. */
  if (block->header.version < 3 && height >= network->softforks.bip66.height)
    return btc_chain_throw(chain, hdr, "obsolete", "bad-version", 0, 0);

  /* Only allow version 4 blocks (checklocktimeverify)
     once the majority of blocks are using it. */
  if (block->header.version < 4 && height >= network->softforks.bip65.height)
    return btc_chain_throw(chain, hdr, "obsolete", "bad-version", 0, 0);

  /* Get the new deployment state. */
  btc_chain_get_deployments(chain, state, block->header.time, prev);

  /* Enforce BIP91/BIP148. */
  if (state->bip91 || state->bip148) {
    const btc_deployment_t *segwit = btc_network_deployment(network, "segwit");

    if (!btc_consensus_has_bit(block->header.version, segwit->bit))
      return btc_chain_throw(chain, hdr, "invalid", "bad-no-segwit", 0, 0);
  }

  /* Get timestamp for tx.isFinal(). */
  time = block->header.time;

  if (state->lock_flags & BTC_CHAIN_MEDIAN_TIME_PAST)
    time = mtp;

  /* Transactions must be finalized with
     regards to nSequence and nLockTime. */
  for (i = 0; i < block->txs.length; i++) {
    const bcoin_tx_t *tx = block->txs.items[i];

    if (!btc_tx_is_final(tx, height, time))
      return btc_chain_throw(chain, hdr, "invalid", "bad-txns-nonfinal", 10, 0);
  }

  /* Make sure the height contained
     in the coinbase is correct. */
  if (state->bip34) {
    if (btc_block_coinbase_height(block) != height)
      return btc_chain_throw(chain, hdr, "invalid", "bad-cb-height", 100, 0);
  }

  /* Check the commitment hash for segwit. */
  has_commit = 0;

  if (state->flags & BTC_SCRIPT_VERIFY_WITNESS) {
    if (btc_block_get_commitment_hash(hash, block)) {
      /* These are totally malleable. Someone
         may have even accidentally sent us
         the non-witness version of the block.
         We don't want to consider this block
         "invalid" if either of these checks
         fail. */
      if (!btc_block_witness_nonce(block)) {
        return btc_chain_throw(chain, hdr,
                               "invalid",
                               "bad-witness-nonce-size",
                               100,
                               1);
      }

      CHECK(btc_block_create_commitment_hash(root, block));

      if (!btc_hash_equal(hash, root)) {
        return btc_chain_throw(chain, hdr,
                               "invalid",
                               "bad-witness-merkle-match",
                               100,
                               1);
      }

      has_commit = 1;
    }
  }

  /* Blocks that do not commit to
     witness data cannot contain it. */
  if (!has_commit) {
    if (!btc_block_has_witness(block)) {
      return btc_chain_throw(chain, hdr,
                             "invalid",
                             "unexpected-witness",
                             100,
                             1);
    }
  }

  /* Check block weight (different from block size
     check in non-contextual verification). */
  if (btc_block_weight(block) > BTC_MAX_BLOCK_WEIGHT) {
    return btc_chain_throw(chain, hdr,
                           "invalid",
                           "bad-blk-weight",
                           100,
                           0);
  }

  return 1;
}

static int
btc_chain_verify_duplicates(btc_chain_t *chain,
                            const btc_block_t *block,
                            btc_entry_t *prev) {
  /**
   * Determine whether to check block for duplicate txids in blockchain
   * history (BIP30). If we're on a chain that has bip34 activated, we
   * can skip this.
   *
   * See: https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki
   */
  const btc_network_t *network = chain->network;
  const btc_header_t *hdr = &block->header;
  const btc_checkpoint_t *chk;
  const btc_tx_t *tx;
  uint8_t hash[32];
  size_t i;

  btc_header_hash(hash, &block->header);

  for (i = 0; i < block->txs.length; i++) {
    tx = block->txs.items[i];

    if (!btc_chaindb_has_coins(chain->db, tx))
      continue;

    chk = btc_network_bip30(network, prev->height + 1);

    /* Blocks 91842 and 91880 created duplicate
       txids by using the same exact output script
       and extraNonce. */
    if (chk == NULL || !btc_hash_equal(hash, chk->hash)) {
      return btc_chain_throw(chain, hdr,
                             "invalid",
                             "bad-txns-BIP30",
                             100,
                             0);
    }
  }

  return 1;
}

static btc_view_t *
btc_chain_update_inputs(btc_chain_t *chain,
                        const btc_block_t *block,
                        btc_entry_t *prev) {
  const btc_tx_t *cb = block->txs.items[0];
  btc_view_t *view = btc_view_create();
  int32_t height = prev->height + 1;
  size_t i;

  btc_view_add(view, cb, height, 0);

  for (i = 1; i < block->txs.length; i++) {
    const btc_tx_t *tx = block->txs.items[i];

    CHECK(btc_chaindb_spend(chain->db, view, tx));

    btc_view_add(view, tx, height, 0);
  }

  return view;
}

static int
btc_chain_verify_final(btc_chain_t *chain,
                       const btc_entry_t *prev,
                       const btc_tx_t *tx,
                       unsigned int flags) {
  int32_t height = prev->height + 1;

  /* We can skip MTP if the locktime is height. */
  if (tx->locktime < BTC_LOCKTIME_THRESHOLD)
    return btc_tx_is_final(tx, height, 0);

  if (flags & BTC_CHAIN_MEDIAN_TIME_PAST) {
    int64_t ts = btc_entry_median_time(prev);
    return btc_tx_is_final(tx, height, ts);
  }

  return btc_tx_is_final(tx, height, btc_timedata_now(chain->time));
}

int
btc_chain_verify_locks(btc_chain_t *chain,
                       const btc_entry_t *prev,
                       const btc_tx_t *tx,
                       btc_view_t *view,
                       unsigned int flags) {
  int32_t min_height = -1;
  int64_t min_time = -1;
  size_t i;

  if (!(flags & BTC_CHAIN_VERIFY_SEQUENCE))
    return 1;

  if (btc_tx_is_coinbase(tx) || tx->version < 2)
    return 1;

  for (i = 0; i < tx->inputs.length; i++) {
    const btc_input_t *input = tx->inputs.items[i];
    const btc_entry_t *entry;
    const btc_coin_t *coin;
    int32_t height;
    int64_t time;

    if (input->sequence & BTC_SEQUENCE_DISABLE_FLAG)
      continue;

    coin = btc_view_get(view, &input->prevout);

    if (coin == NULL || coin->height == -1)
      height = chain->height + 1;
    else
      height = coin->height;

    if (!(input->sequence & BTC_SEQUENCE_TYPE_FLAG)) {
      height += (input->sequence & BTC_SEQUENCE_MASK) - 1;

      if (height > min_height)
        min_height = height;

      continue;
    }

    if (height > 0)
      height -= 1;

    entry = btc_chain_get_ancestor(chain, prev, height);

    CHECK(entry != NULL);

    time = btc_entry_median_time(entry);

    time += ((input->sequence & BTC_SEQUENCE_MASK) << BTC_SEQUENCE_GRANULARITY) - 1;

    if (time > min_time)
      min_time = time;
  }

  if (min_height != -1) {
    if (min_height >= prev->height + 1)
      return 0;
  }

  if (min_time != -1) {
    if (min_time >= btc_entry_median_time(prev))
      return 0;
  }

  return 1;
}

static btc_view_t *
btc_chain_verify_inputs(btc_chain_t *chain,
                        const btc_block_t *block,
                        btc_entry_t *prev,
                        const btc_dstate_t *state) {
  const btc_header_t *hdr = &block->header;
  int32_t interval = chain->network->halving_interval;
  btc_view_t *view = btc_view_create();
  int32_t height = prev->height + 1;
  btc_verify_error_t err;
  int64_t reward = 0;
  int sigops = 0;
  size_t i;

  /* Check all transactions. */
  for (i = 0; i < block->txs.length; i++) {
    const btc_tx_t *tx = block->txs.items[i];

    /* Ensure tx is not double spending an output. */
    if (i > 0) {
      if (!btc_chaindb_spend(chain->db, view, tx)) {
        return btc_chain_throw(chain, hdr,
                               "invalid",
                               "bad-txns-inputs-missingorspent",
                               100,
                               0);
      }
    }

    /* Verify sequence locks. */
    if (i > 0 && tx.version >= 2) {
      if (!btc_chain_verify_locks(chain, prev, tx, view, state->lock_flags)) {
        return btc_chain_throw(chain, hdr,
                               "invalid",
                               "bad-txns-nonfinal",
                               100,
                               0);
      }
    }

    /* Count sigops (legacy + scripthash? + witness?). */
    sigops += btc_tx_sigops_cost(tx, view, state->flags);

    if (sigops > BTC_MAX_BLOCK_SIGOPS_COST) {
      return btc_chain_throw(chain, hdr,
                             "invalid",
                             "bad-blk-sigops",
                             100,
                             0);
    }

    /* Contextual sanity checks. */
    if (i > 0) {
      int64_t fee = btc_check_inputs(&err, tx, view, height);

      if (fee == -1) {
        return btc_chain_throw(chain, hdr,
                               "invalid",
                               err.reason,
                               err.score,
                               0);
      }

      reward += fee;

      if (reward < 0 || reward > BTC_MAX_MONEY) {
        return btc_chain_throw(chain, hdr,
                               "invalid",
                               "bad-cb-amount",
                               100,
                               0);
      }
    }

    btc_view_add(view, tx, height, 0);
  }

  /* Make sure the miner isn't trying to conjure more coins. */
  reward += btc_consensus_get_reward(height, interval);

  if (btc_block_claimed(block) > reward) {
    return btc_chain_throw(chain, hdr,
                           "invalid",
                           "bad-cb-amount",
                           100,
                           0);
  }

  /* Verify all transactions. */
  for (i = 1; i < block->txs.length; i++) {
    const btc_tx_t *tx = block->txs.items[i];

    if (!btc_tx_verify(tx, view, state->flags)) {
      return btc_chain_throw(chain, hdr,
                             "invalid",
                             "mandatory-script-verify-flag-failed",
                             100,
                             0);
    }
  }

  return view;
}

static btc_view_t *
btc_chain_verify_context(btc_chain_t *chain,
                         btc_dstate_t *state,
                         const btc_block_t *block,
                         btc_entry_t *prev,
                         unsigned int flags) {
  /* Initial non-contextual verification. */
  if (!btc_chain_verify(chain, state, block, prev, flags))
    return NULL;

  /* Skip everything if we're using checkpoints. */
  if (btc_chain_is_historical(chain, prev))
    return btc_chain_update_inputs(chain, block, prev);

  /* BIP30 - Verify there are no duplicate txids.
     Note that BIP34 made it impossible to create
     duplicate txids. */
  if (!state->bip34) {
    if (!btc_chain_verify_duplicates(chain, block, prev))
      return NULL;
  }

  /* Verify scripts, spend and add coins. */
  return btc_chain_verify_inputs(chain, block, prev, state);
}

int
btc_chain_add(btc_chain_t *chain, btc_block_t *block, unsigned int flags, int id) {
  const btc_header_t *hdr = &block->header;
  btc_entry_t *prev, *entry;
  uint8_t hash[32];

  btc_header_hash(hash, &block->header);

  /* Special case for genesis block. */
  if (btc_hash_equal(hash, chain->network->genesis.hash)) {
    btc_chain_log(chain, "Saw genesis block: %h.\n", hash);
    return btc_chain_throw(chain, hdr, "duplicate", "duplicate", 0, 0);
  }

  /* If the block is already known to be
     an orphan, ignore it. */
  if (btc_chain_has_orphan(chain, hash)) {
    btc_chain_log(chain, "Already have orphan block: %h.\n", hash);
    return btc_chain_throw(chain, hdr, "duplicate", "duplicate", 0, 0);
  }

  /* Do not revalidate known invalid blocks. */
  if (btc_chain_has_invalid(chain, hash)) {
    btc_chain_log(chain, "Invalid ancestors for block: %h.\n", hash);
    return btc_chain_throw(chain, hdr, "duplicate", "duplicate", 100, 0);
  }

  /* Check the PoW before doing anything. */
  if (flags & BTC_CHAIN_VERIFY_POW) {
    if (!btc_header_verify(&block->header))
      return btc_chain_throw(chain, hdr, "invalid", "high-hash", 50, 0);
  }

  /* Do we already have this block? */
  if (btc_chain_has_entry(chain, hash)) {
    btc_chain_log(chain, "Already have block: %h.\n", hash);
    return btc_chain_throw(chain, hdr, "duplicate", "duplicate", 0, 0);
  }

  /* Find the previous block entry. */
  prev = btc_chaindb_by_hash(chain->db, block->header.prev_block);

  /* If previous block wasn't ever seen,
     add it current to orphans and return. */
  if (prev == NULL) {
    btc_chain_store_orphan(chain, block, id);
    return 1;
  }

  /* Connect the block. */
  entry = btc_chain_connect(chain, prev, block, flags);

  if (entry == NULL)
    return 0;

  /* Handle any orphans. */
  if (btc_chain_has_next_orphan(chain, hash))
    btc_chain_handle_orphans(chain, entry);

  return 1;
}

static btc_entry_t *
btc_chain_connect(btc_chain_t *chain,
                  const btc_entry_t *prev,
                  btc_block_t *block,
                  unsigned int flags) {
  btc_entry_t *entry = btc_entry_create();

  btc_entry_set_block(entry, block, prev);

  if (btc_hash_compare(entry->chainwork, chain->tip->chainwork) <= 0) {
    if (!btc_chain_save_alternate(chain, entry, block, flags)) {
      btc_entry_destroy(entry);
      return NULL;
    }
  } else {
    if (!btc_chain_set_best_chain(chain, entry, block, flags)) {
      btc_entry_destroy(entry);
      return NULL;
    }
  }

  return entry;
}

static int
btc_chain_save_alternate(btc_chain_t *chain,
                         btc_entry_t *entry,
                         btc_block_t *block,
                         unsigned int flags) {
  const btc_header_t *hdr = &block->header;
  btc_dstate_t state;
  int ret = 0;

  if (chain->checkpoints_enabled) {
    if (entry->height < chain->network->last_checkpoint) {
      btc_chain_throw(chain, hdr,
                      "checkpoint",
                      "bad-fork-prior-to-checkpoint",
                      100,
                      0);
      goto fail;
    }
  }

  if (!btc_chain_verify(chain, &state, block, entry->prev, flags)) {
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
                         btc_entry_t *entry,
                         btc_block_t *block,
                         unsigned int flags) {
  const btc_entry_t *fork = NULL;
  btc_entry_t *tip = chain->tip;
  btc_dstate_t state;
  btc_view_t *view;
  int ret = 0;

  /* A higher fork has arrived. Time to reorganize the chain. */
  if (!btc_hash_equal(entry->header.prev_block, tip->hash)) {
    /* Do as much verification as we can before reorganizing. */
    if (!btc_chain_verify(chain, &state, block, entry->prev, flags)) {
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
  view = btc_chain_verify_context(chain, &state, block, entry->prev, flags);

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
  }

  chain->on_reorganize(chain->arg, tip, competitor);

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

  chain->on_reorganize(chain->arg, tip, last);

  btc_vector_clear(&disconnect);
  btc_vector_clear(&connect);
}

static int
btc_chain_reconnect(btc_chain_t *chain, const btc_entry_t *entry) {
  unsigned int flags = BTC_CHAIN_VERIFY_NONE;
  btc_dstate_t state;
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
btc_chain_get_target(btc_chain_t *chain,
                     int64_t time,
                     const btc_entry_t *prev) {
  const btc_network_t *net = chain->network;
  const btc_entry_t *first;
  int32_t height;

  if (prev == NULL) {
    CHECK(time == net->genesis.header.time);
    return net->pow.bits;
  }

  /* Do not retarget. */
  if ((prev->height + 1) % net->pow.retarget_interval != 0) {
    if (net->pow.target_reset) {
      /* Special behavior for testnet. */
      if (time > prev->time + net->pow.target_spacing * 2)
        return net->pow.bits;

      while (prev->prev != NULL
             && prev->height % net->pow.retarget_interval != 0
             && prev->header.bits == net->pow.bits) {
        prev = prev->prev;
      }
    }

    return prev->header.bits;
  }

  /* Back 2 weeks. */
  height = prev->height - (net->pow.retarget_interval - 1);

  CHECK(height >= 0);

  first = btc_chain_get_ancestor(chain, prev, height);

  CHECK(first != NULL);

  return btc_chain_retarget(chain, prev, first);
}

static uint32_t
btc_chain_retarget(btc_chain_t *chain,
                   const btc_entry_t *prev,
                   const btc_entry_t *first) {
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

  actual_timespan = prev->header.time - first->header.time;

  if (actual_timespan < target_timespan / 4)
    actual_timespan = target_timespan / 4;

  if (actual_timespan > target_timespan * 4)
    actual_timespan = target_timespan * 4;

  mpz_mul(target, target, actual_timespan);
  mpz_quo(target, target, target_timespan);

  if (mpz_cmp(target, limit) <= 0)
    ret = mpz_get_compact(target);
  else
    ret = net->pow.bits;

  mpz_clear(limit);
  mpz_clear(target);

  return ret;
}
