/*!
 * bip37.c - bip37 for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mako/array.h>
#include <mako/bip37.h>
#include <mako/block.h>
#include <mako/buffer.h>
#include <mako/consensus.h>
#include <mako/crypto/hash.h>
#include <mako/header.h>
#include <mako/map.h>
#include <mako/tx.h>
#include <mako/util.h>
#include <mako/vector.h>
#include "impl.h"
#include "internal.h"

/*
 * Merkle Block
 */

DEFINE_SERIALIZABLE_OBJECT(btc_merkleblock, SCOPE_EXTERN)

void
btc_merkleblock_init(btc_merkleblock_t *z) {
  btc_header_init(&z->header);
  z->total = 0;
  btc_vector_init(&z->hashes);
  btc_buffer_init(&z->flags);
  btc_vector_init(&z->matches);
  btc_array_init(&z->indices);
}

static void
btc_merkleblock_reset(btc_merkleblock_t *z) {
  while (z->hashes.length > 0)
    btc_free(btc_vector_pop(&z->hashes));

  btc_buffer_reset(&z->flags);
  btc_vector_reset(&z->matches);
  btc_array_reset(&z->indices);
}

void
btc_merkleblock_clear(btc_merkleblock_t *z) {
  btc_merkleblock_reset(z);
  btc_header_clear(&z->header);
  btc_vector_clear(&z->hashes);
  btc_buffer_clear(&z->flags);
  btc_vector_clear(&z->matches);
  btc_array_clear(&z->indices);
}

void
btc_merkleblock_copy(btc_merkleblock_t *z, const btc_merkleblock_t *x) {
  size_t i;

  btc_merkleblock_reset(z);

  btc_header_copy(&z->header, &x->header);

  z->total = x->total;

  btc_vector_resize(&z->hashes, x->hashes.length);

  for (i = 0; i < x->hashes.length; i++)
    z->hashes.items[i] = btc_hash_clone(x->hashes.items[i]);

  btc_buffer_copy(&z->flags, &x->flags);
}

size_t
btc_merkleblock_size(const btc_merkleblock_t *block) {
  size_t size = 0;

  size += btc_header_size(&block->header);
  size += 4;
  size += btc_size_size(block->hashes.length);
  size += block->hashes.length * 32;
  size += btc_buffer_size(&block->flags);

  return size;
}

uint8_t *
btc_merkleblock_write(uint8_t *zp, const btc_merkleblock_t *x) {
  size_t i;

  zp = btc_header_write(zp, &x->header);
  zp = btc_uint32_write(zp, x->total);
  zp = btc_size_write(zp, x->hashes.length);

  for (i = 0; i < x->hashes.length; i++)
    zp = btc_raw_write(zp, x->hashes.items[i], 32);

  zp = btc_buffer_write(zp, &x->flags);

  return zp;
}

int
btc_merkleblock_read(btc_merkleblock_t *z, const uint8_t **xp, size_t *xn) {
  const uint8_t *hash;
  size_t i, len;

  if (!btc_header_read(&z->header, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->total, xp, xn))
    return 0;

  if (!btc_size_read(&len, xp, xn))
    return 0;

  btc_merkleblock_reset(z);

  for (i = 0; i < len; i++) {
    if (!btc_zraw_read(&hash, 32, xp, xn))
      return 0;

    btc_vector_push(&z->hashes, btc_hash_clone(hash));
  }

  if (!btc_buffer_read(&z->flags, xp, xn))
    return 0;

  return 1;
}

static uint32_t
tree_width(const btc_merkleblock_t *tree, int32_t height) {
  return (tree->total + (1 << height) - 1) >> height;
}

static int
tree_traverse(uint8_t *root,
              const btc_merkleblock_t *tree,
              int32_t height,
              uint32_t pos,
              uint32_t *bits_used,
              uint32_t *hash_used,
              btc_vector_t *matches,
              btc_array_t *indices) {
  int parent;

  if (*bits_used >= tree->flags.length * 8)
    return 0;

  parent = (tree->flags.data[*bits_used >> 3] >> (*bits_used & 7)) & 1;

  *bits_used += 1;

  if (height == 0 || !parent) {
    const uint8_t *hash;

    if (*hash_used >= tree->hashes.length)
      return 0;

    hash = tree->hashes.items[*hash_used];

    *hash_used += 1;

    if (height == 0 && parent) {
      btc_vector_push(matches, hash);
      btc_array_push(indices, pos);
    }

    btc_hash_copy(root, hash);
  } else {
    uint8_t left[32], right[32];

    if (!tree_traverse(left, tree,
                       height - 1, pos * 2 + 0,
                       bits_used, hash_used,
                       matches, indices)) {
      return 0;
    }

    if (pos * 2 + 1 < tree_width(tree, height - 1)) {
      if (!tree_traverse(right, tree,
                         height - 1, pos * 2 + 1,
                         bits_used, hash_used,
                         matches, indices)) {
        return 0;
      }

      if (btc_hash_equal(right, left))
        return 0;
    } else {
      btc_hash_copy(right, left);
    }

    btc_hash256_root(root, left, right);
  }

  return 1;
}

static int
btc_merkleblock_extract(uint8_t *root,
                        btc_vector_t *matches,
                        btc_array_t *indices,
                        const btc_merkleblock_t *block) {
  uint32_t bits_used = 0;
  uint32_t hash_used = 0;
  int32_t height = 0;

  if (block->total == 0)
    return 0;

  if (block->total > BTC_MAX_BLOCK_SIZE / 60)
    return 0;

  if (block->hashes.length > block->total)
    return 0;

  if (block->flags.length * 8 < block->hashes.length)
    return 0;

  while (tree_width(block, height) > 1)
    height += 1;

  if (!tree_traverse(root, block,
                     height, 0,
                     &bits_used, &hash_used,
                     matches, indices)) {
    return 0;
  }

  if (((bits_used + 7) >> 3) != block->flags.length)
    return 0;

  if (hash_used != block->hashes.length)
    return 0;

  return 1;
}

int
btc_merkleblock_verify(btc_merkleblock_t *block) {
  uint8_t root[32];

  btc_vector_reset(&block->matches);
  btc_array_reset(&block->indices);

  if (!btc_header_verify(&block->header))
    return 0;

  if (!btc_merkleblock_extract(root, &block->matches, &block->indices, block))
    return 0;

  if (!btc_hash_equal(root, block->header.merkle_root))
    return 0;

  return 1;
}

static void
tree_hash(uint8_t *root,
          const btc_merkleblock_t *tree,
          int32_t height,
          uint32_t pos,
          const btc_vector_t *leaves) {
  if (height == 0) {
    btc_hash_copy(root, leaves->items[pos]);
  } else {
    uint8_t left[32], right[32];

    tree_hash(left, tree, height - 1, pos * 2 + 0, leaves);

    if (pos * 2 + 1 < tree_width(tree, height - 1))
      tree_hash(right, tree, height - 1, pos * 2 + 1, leaves);
    else
      btc_hash_copy(right, left);

    btc_hash256_root(root, left, right);
  }
}

static void
tree_build(btc_merkleblock_t *tree,
           int32_t height,
           uint32_t pos,
           const btc_vector_t *leaves,
           const btc_array_t *matches,
           btc_array_t *bits) {
  int parent = 0;
  uint32_t p;

  for (p = pos << height; p < ((pos + 1) << height) && p < tree->total; p++)
    parent |= matches->items[p];

  btc_array_push(bits, !!parent);

  if (height == 0 || !parent) {
    uint8_t *root = (uint8_t *)btc_malloc(32);

    tree_hash(root, tree, height, pos, leaves);

    btc_vector_push(&tree->hashes, root);
  } else {
    tree_build(tree, height - 1, pos * 2 + 0, leaves, matches, bits);

    if (pos * 2 + 1 < tree_width(tree, height - 1))
      tree_build(tree, height - 1, pos * 2 + 1, leaves, matches, bits);
  }
}

static void
btc_merkleblock_set_matches(btc_merkleblock_t *tree,
                            const btc_block_t *block,
                            const btc_array_t *matches) {
  btc_vector_t leaves;
  btc_array_t bits;
  int32_t height = 0;
  size_t i, p;

  CHECK(block->txs.length > 0);

  btc_vector_init(&leaves);
  btc_array_init(&bits);

  btc_merkleblock_reset(tree);

  btc_header_copy(&tree->header, &block->header);

  tree->total = block->txs.length;

  btc_vector_resize(&leaves, block->txs.length);

  for (i = 0; i < block->txs.length; i++)
    leaves.items[i] = block->txs.items[i]->hash;

  while (tree_width(tree, height) > 1)
    height += 1;

  tree_build(tree, height, 0, &leaves, matches, &bits);

  btc_buffer_resize(&tree->flags, (bits.length + 7) / 8);

  memset(tree->flags.data, 0, tree->flags.length);

  for (p = 0; p < bits.length; p++)
    tree->flags.data[p >> 3] |= bits.items[p] << (p & 7);

  btc_vector_clear(&leaves);
  btc_array_clear(&bits);
}

btc_vector_t *
btc_merkleblock_set_block(btc_merkleblock_t *tree,
                          const btc_block_t *block,
                          btc_bloom_t *filter) {
  btc_vector_t *txs = btc_vector_create();
  btc_array_t matches;
  size_t i;

  btc_array_init(&matches);
  btc_array_resize(&matches, block->txs.length);

  for (i = 0; i < block->txs.length; i++) {
    const btc_tx_t *tx = block->txs.items[i];
    int match = btc_tx_matches(tx, filter);

    if (match)
      btc_vector_push(txs, tx);

    matches.items[i] = match;
  }

  btc_merkleblock_set_matches(tree, block, &matches);

  btc_array_clear(&matches);

  return txs;
}

void
btc_merkleblock_set_hashes(btc_merkleblock_t *tree,
                           const btc_block_t *block,
                           const btc_vector_t *hashes) {
  btc_hashset_t *filter = btc_hashset_create();
  btc_array_t matches;
  size_t i;

  btc_array_init(&matches);

  for (i = 0; i < hashes->length; i++)
    btc_hashset_put(filter, hashes->items[i]);

  btc_array_resize(&matches, block->txs.length);

  for (i = 0; i < block->txs.length; i++) {
    const btc_tx_t *tx = block->txs.items[i];

    matches.items[i] = btc_hashset_has(filter, tx->hash);
  }

  btc_merkleblock_set_matches(tree, block, &matches);

  btc_hashset_destroy(filter);
  btc_array_clear(&matches);
}
