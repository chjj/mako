/*!
 * entry.c - entry for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/consensus.h>
#include <satoshi/entry.h>
#include <satoshi/header.h>
#include <satoshi/mpi.h>
#include <satoshi/util.h>
#include "impl.h"
#include "internal.h"

/*
 * Chain Entry
 */

DEFINE_SERIALIZABLE_OBJECT(btc_entry, SCOPE_EXTERN)

void
btc_entry_init(btc_entry_t *z) {
  btc_hash_init(z->hash);
  btc_header_init(&z->header);
  z->height = 0;
  memset(z->chainwork, 0, 32);
  z->block_file = -1;
  z->block_pos = -1;
  z->undo_file = -1;
  z->undo_pos = -1;
  z->prev = NULL;
  z->next = NULL;
}

void
btc_entry_clear(btc_entry_t *z) {
  btc_header_clear(&z->header);
}

void
btc_entry_copy(btc_entry_t *z, const btc_entry_t *x) {
  btc_hash_copy(z->hash, x->hash);
  btc_header_copy(&z->header, &x->header);
  z->height = x->height;
  memcpy(z->chainwork, x->chainwork, 32);
  z->block_file = x->block_file;
  z->block_pos = x->block_pos;
  z->undo_file = x->undo_file;
  z->undo_pos = x->undo_pos;
  z->prev = NULL;
  z->next = NULL;
}

size_t
btc_entry_size(const btc_entry_t *x) {
  size_t size = 0;

  size += btc_header_size(&x->header);
  size += 4;
  size += 32;
  size += 4;
  size += 4;
  size += 4;
  size += 4;

  return size;
}

uint8_t *
btc_entry_write(uint8_t *zp, const btc_entry_t *x) {
  zp = btc_header_write(zp, &x->header);
  zp = btc_int32_write(zp, x->height);
  zp = btc_raw_write(zp, x->chainwork, 32);
  zp = btc_int32_write(zp, x->block_file);
  zp = btc_int32_write(zp, x->block_pos);
  zp = btc_int32_write(zp, x->undo_file);
  zp = btc_int32_write(zp, x->undo_pos);
  return zp;
}

int
btc_entry_read(btc_entry_t *z, const uint8_t **xp, size_t *xn) {
  btc_entry_init(z);

  if (!btc_header_read(&z->header, xp, xn))
    return 0;

  if (!btc_int32_read(&z->height, xp, xn))
    return 0;

  if (!btc_raw_read(z->chainwork, 32, xp, xn))
    return 0;

  if (!btc_int32_read(&z->block_file, xp, xn))
    return 0;

  if (!btc_int32_read(&z->block_pos, xp, xn))
    return 0;

  if (!btc_int32_read(&z->undo_file, xp, xn))
    return 0;

  if (!btc_int32_read(&z->undo_pos, xp, xn))
    return 0;

  btc_header_hash(z->hash, &z->header);

  return 1;
}

void
btc_entry_get_chainwork(uint8_t *chainwork,
                        const btc_entry_t *entry,
                        const btc_entry_t *prev) {
#if MP_LIMB_BITS == 64
  static mp_limb_t limbs[5] = {0, 0, 0, 0, 1};
  static const mpz_t max = MPZ_ROINIT_N(limbs, 5);
#else
  static mp_limb_t limbs[9] = {0, 0, 0, 0, 0, 0, 0, 0, 1};
  static const mpz_t max = MPZ_ROINIT_N(limbs, 9);
#endif
  mpz_t work, target, proof;

  mpz_init(work);
  mpz_init(target);
  mpz_init(proof);

  if (prev != NULL)
    mpz_import(work, prev->chainwork, 32, -1);

  mpz_set_compact(target, entry->header.bits);

  CHECK(mpz_sgn(target) >= 0);
  CHECK(mpz_bitlen(target) <= 256);

  mpz_add_ui(target, target, 1);
  mpz_quo(proof, max, target);

  mpz_add(work, work, proof);
  mpz_export(chainwork, work, 32, -1);

  mpz_clear(work);
  mpz_clear(target);
  mpz_clear(proof);
}

void
btc_entry_set_header(btc_entry_t *entry,
                     const btc_header_t *hdr,
                     const btc_entry_t *prev) {
  btc_entry_init(entry);

  btc_header_hash(entry->hash, hdr);
  btc_header_copy(&entry->header, hdr);

  entry->height = prev != NULL ? prev->height + 1 : 0;

  btc_entry_get_chainwork(entry->chainwork, entry, prev);

  entry->prev = (btc_entry_t *)prev;
}

void
btc_entry_set_block(btc_entry_t *entry,
                    const btc_block_t *block,
                    const btc_entry_t *prev) {
  btc_entry_set_header(entry, &block->header, prev);
}

static int
cmptime(const void *x, const void *y) {
  return *((int64_t *)x) - *((int64_t *)y);
}

int64_t
btc_entry_median_time(const btc_entry_t *entry) {
  int64_t tvec[BTC_MEDIAN_TIMESPAN];
  int len = 0;
  int i;

  for (i = 0; i < BTC_MEDIAN_TIMESPAN && entry != NULL; i++) {
    tvec[len++] = entry->header.time;
    entry = entry->prev;
  }

  qsort(tvec, len, sizeof(int64_t), cmptime);

  return tvec[len >> 1];
}

int64_t
btc_entry_bip148_time(const btc_entry_t *prev, int64_t ts) {
  int64_t tvec[BTC_MEDIAN_TIMESPAN];
  int len = 0;
  int i;

  tvec[len++] = ts;

  for (i = 1; i < BTC_MEDIAN_TIMESPAN && prev != NULL; i++) {
    tvec[len++] = prev->header.time;
    prev = prev->prev;
  }

  qsort(tvec, len, sizeof(int64_t), cmptime);

  return tvec[len >> 1];
}
