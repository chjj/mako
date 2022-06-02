/*!
 * dbformat.c - db format for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "util/bloom.h"
#include "util/buffer.h"
#include "util/coding.h"
#include "util/comparator.h"
#include "util/internal.h"
#include "util/slice.h"

#include "dbformat.h"

/*
 * Helpers
 */

static uint64_t
pack_seqtype(uint64_t sequence, ldb_valtype_t type) {
  assert(sequence <= LDB_MAX_SEQUENCE);
  assert(type <= LDB_VALTYPE_SEEK);
  return (sequence << 8) | type;
}

/*
 * ParsedInternalKey
 */

void
ldb_pkey_init(ldb_pkey_t *key,
              const ldb_slice_t *user_key,
              ldb_seqnum_t sequence,
              ldb_valtype_t type) {
  /* This function is called by dbiter_seek,
   * so we try to avoid this in case the user
   * passed a partially initialized struct.
   *
   *   key->user_key = *user_key;
   *
   * Partially initialized struct assignment
   * is supposed to be well-defined[1], but
   * who knows.
   *
   * [1] https://stackoverflow.com/questions/35492055
   */
  ldb_slice_set(&key->user_key, user_key->data,
                                user_key->size);

  key->sequence = sequence;
  key->type = type;
}

size_t
ldb_pkey_size(const ldb_pkey_t *x) {
  return x->user_key.size + 8;
}

static uint8_t *
ldb_pkey_write(uint8_t *zp, const ldb_pkey_t *x) {
  zp = ldb_raw_write(zp, x->user_key.data, x->user_key.size);
  zp = ldb_fixed64_write(zp, pack_seqtype(x->sequence, x->type));
  return zp;
}

void
ldb_pkey_export(ldb_buffer_t *z, const ldb_pkey_t *x) {
  uint8_t *zp = ldb_buffer_expand(z, x->user_key.size + 8);
  size_t xn = ldb_pkey_write(zp, x) - zp;

  z->size += xn;
}

int
ldb_pkey_import(ldb_pkey_t *z, const ldb_slice_t *x) {
  const uint8_t *xp = x->data;
  size_t xn = x->size;
  uint64_t num;
  int type;

  if (xn < 8)
    return 0;

  num = ldb_fixed64_decode(xp + xn - 8);
  type = num & 0xff;

  if (type > LDB_TYPE_VALUE)
    return 0;

  ldb_slice_set(&z->user_key, xp, xn - 8);

  z->sequence = num >> 8;
  z->type = (ldb_valtype_t)type;

  return 1;
}

void
ldb_pkey_debug(ldb_buffer_t *z, const ldb_pkey_t *x) {
  ldb_buffer_push(z, '\'');
  ldb_buffer_escape(z, &x->user_key);
  ldb_buffer_string(z, "' @ ");
  ldb_buffer_number(z, x->sequence);
  ldb_buffer_string(z, " : ");
  ldb_buffer_number(z, x->type);
}

/*
 * InternalKey
 */

void
ldb_ikey_init(ldb_ikey_t *ikey) {
  ldb_buffer_init(ikey);
}

void
ldb_ikey_set(ldb_ikey_t *ikey,
             const ldb_slice_t *user_key,
             ldb_seqnum_t sequence,
             ldb_valtype_t type) {
  ldb_pkey_t pkey;

  ldb_buffer_reset(ikey);

  ldb_pkey_init(&pkey, user_key, sequence, type);
  ldb_pkey_export(ikey, &pkey);
}

void
ldb_ikey_clear(ldb_ikey_t *ikey) {
  ldb_buffer_clear(ikey);
}

void
ldb_ikey_copy(ldb_ikey_t *z, const ldb_ikey_t *x) {
  ldb_buffer_copy(z, x);
}

void
ldb_ikey_export(ldb_ikey_t *z, const ldb_ikey_t *x) {
  ldb_buffer_export(z, x);
}

void
ldb_ikey_debug(ldb_buffer_t *z, const ldb_ikey_t *x) {
  ldb_pkey_t pkey;

  if (ldb_pkey_import(&pkey, x)) {
    ldb_pkey_debug(z, &pkey);
    return;
  }

  ldb_buffer_string(z, "(bad)");
  ldb_buffer_escape(z, x);
}

/*
 * LookupKey
 */

void
ldb_lkey_init(ldb_lkey_t *lkey,
              const ldb_slice_t *user_key,
              ldb_seqnum_t sequence) {
  size_t usize = user_key->size;
  size_t needed = usize + 13; /* A conservative estimate. */
  uint8_t *zp = lkey->space;

  if (needed > sizeof(lkey->space))
    zp = ldb_malloc(needed);

  lkey->start = zp;

  zp = ldb_varint32_write(zp, usize + 8);

  lkey->kstart = zp;

  zp = ldb_raw_write(zp, user_key->data, usize);
  zp = ldb_fixed64_write(zp, pack_seqtype(sequence, LDB_VALTYPE_SEEK));

  lkey->end = zp;
}

void
ldb_lkey_clear(ldb_lkey_t *lkey) {
  if (lkey->start != lkey->space)
    ldb_free((void *)lkey->start);
}

/*
 * InternalKeyComparator
 */

static int
ldb_ikc_compare(const ldb_comparator_t *ikc,
                const ldb_slice_t *x,
                const ldb_slice_t *y) {
  /* Order by:
   *    increasing user key (according to user-supplied comparator)
   *    decreasing sequence number
   *    decreasing type (though sequence# should be enough to disambiguate)
   */
  ldb_slice_t xk = ldb_extract_user_key(x);
  ldb_slice_t yk = ldb_extract_user_key(y);
  int r = ldb_compare(ikc->user_comparator, &xk, &yk);

  if (r == 0) {
    uint64_t xn = ldb_fixed64_decode(x->data + x->size - 8);
    uint64_t yn = ldb_fixed64_decode(y->data + y->size - 8);

    if (xn > yn)
      r = -1;
    else if (xn < yn)
      r = +1;
  }

  return r;
}

static void
ldb_ikc_shortest_separator(const ldb_comparator_t *ikc,
                           ldb_buffer_t *start,
                           const ldb_slice_t *limit) {
  /* Attempt to shorten the user portion of the key. */
  const ldb_comparator_t *uc = ikc->user_comparator;
  ldb_slice_t user_start = ldb_extract_user_key(start);
  ldb_slice_t user_limit = ldb_extract_user_key(limit);
  ldb_buffer_t tmp;

  ldb_buffer_init(&tmp);
  ldb_buffer_grow(&tmp, user_start.size + 8);
  ldb_buffer_copy(&tmp, &user_start);

  ldb_shortest_separator(uc, &tmp, &user_limit);

  if (tmp.size < user_start.size && ldb_compare(uc, &user_start, &tmp) < 0) {
    /* User key has become shorter physically, but larger logically. */
    /* Tack on the earliest possible number to the shortened user key. */
    ldb_buffer_fixed64(&tmp, pack_seqtype(LDB_MAX_SEQUENCE, LDB_VALTYPE_SEEK));

    assert(ldb_compare(ikc, start, &tmp) < 0);
    assert(ldb_compare(ikc, &tmp, limit) < 0);

    ldb_buffer_swap(start, &tmp);
  }

  ldb_buffer_clear(&tmp);
}

static void
ldb_ikc_short_successor(const ldb_comparator_t *ikc, ldb_buffer_t *key) {
  const ldb_comparator_t *uc = ikc->user_comparator;
  ldb_slice_t user_key = ldb_extract_user_key(key);
  ldb_buffer_t tmp;

  ldb_buffer_init(&tmp);
  ldb_buffer_grow(&tmp, user_key.size + 8);
  ldb_buffer_copy(&tmp, &user_key);

  ldb_short_successor(uc, &tmp);

  if (tmp.size < user_key.size && ldb_compare(uc, &user_key, &tmp) < 0) {
    /* User key has become shorter physically, but larger logically. */
    /* Tack on the earliest possible number to the shortened user key. */
    ldb_buffer_fixed64(&tmp, pack_seqtype(LDB_MAX_SEQUENCE, LDB_VALTYPE_SEEK));

    assert(ldb_compare(ikc, key, &tmp) < 0);

    ldb_buffer_swap(key, &tmp);
  }

  ldb_buffer_clear(&tmp);
}

void
ldb_ikc_init(ldb_comparator_t *ikc, const ldb_comparator_t *user_comparator) {
  ikc->name = "leveldb.InternalKeyComparator";
  ikc->compare = ldb_ikc_compare;
  ikc->shortest_separator = NULL;
  ikc->short_successor = NULL;
  ikc->user_comparator = user_comparator;
  ikc->state = NULL;

  if (user_comparator->shortest_separator != NULL)
    ikc->shortest_separator = ldb_ikc_shortest_separator;

  if (user_comparator->short_successor != NULL)
    ikc->short_successor = ldb_ikc_short_successor;
}

/*
 * InternalFilterPolicy
 */

static void
ldb_ifp_build(const ldb_bloom_t *ifp,
              ldb_buffer_t *dst,
              const ldb_slice_t *keys,
              size_t length) {
  ldb_slice_t *ukeys = ldb_malloc(length * sizeof(ldb_slice_t));
  size_t i;

  for (i = 0; i < length; i++)
    ukeys[i] = ldb_extract_user_key(&keys[i]);

  ldb_bloom_build(ifp->user_policy, dst, ukeys, length);
  ldb_free(ukeys);
}

static int
ldb_ifp_match(const ldb_bloom_t *ifp,
              const ldb_slice_t *filter,
              const ldb_slice_t *key) {
  ldb_slice_t k = ldb_extract_user_key(key);

  return ldb_bloom_match(ifp->user_policy, filter, &k);
}

void
ldb_ifp_init(ldb_bloom_t *ifp, const ldb_bloom_t *user_policy) {
  ifp->name = user_policy->name;
  ifp->build = ldb_ifp_build;
  ifp->match = ldb_ifp_match;
  ifp->bits_per_key = 0;
  ifp->k = 0;
  ifp->user_policy = user_policy;
  ifp->state = NULL;
}
