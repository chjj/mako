/*!
 * entry.c - entry for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <satoshi/entry.h>
#include <satoshi/header.h>
#include <satoshi/mpi.h>
#include "impl.h"
#include "internal.h"

/*
 * Chain Entry
 */

DEFINE_SERIALIZABLE_OBJECT(btc_entry, SCOPE_EXTERN)

void
btc_entry_init(btc_entry_t *z) {
  memset(z->hash, 0, 32);
  btc_header_init(&z->header);
  z->height = 0;
  memset(z->chainwork, 0, 32);
  z->prev = NULL;
  z->next = NULL;
}

void
btc_entry_clear(btc_entry_t *z) {
  btc_header_clear(&z->header);
}

void
btc_entry_copy(btc_entry_t *z, const btc_entry_t *x) {
  memcpy(z->hash, x->hash, 32);
  btc_header_copy(&z->header, &x->header);
  z->height = x->height;
  memcpy(z->chainwork, x->chainwork, 32);
}

size_t
btc_entry_size(const btc_entry_t *x) {
  size_t size = 0;

  size += btc_header_size(&x->header);
  size += 4;
  size += 32;

  return size;
}

uint8_t *
btc_entry_write(uint8_t *zp, const btc_entry_t *x) {
  zp = btc_header_write(zp, &x->header);
  zp = btc_uint32_write(zp, x->height);
  zp = btc_raw_write(zp, x->chainwork, 32);
  return zp;
}

int
btc_entry_read(btc_entry_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_header_read(&z->header, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->height, xp, xn))
    return 0;

  if (!btc_raw_read(z->chainwork, 32, xp, xn))
    return 0;

  btc_header_hash(z->hash, &z->header);

  z->prev = NULL;
  z->next = NULL;

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
  btc_header_hash(entry->hash, hdr);

  entry->header = *hdr;
  entry->height = prev != NULL ? prev->height + 1 : 0;

  btc_entry_get_chainwork(entry->chainwork, entry, prev);

  entry->prev = prev;
}

void
btc_entry_set_block(btc_entry_t *entry,
                    const btc_block_t *block,
                    const btc_entry_t *prev) {
  btc_entry_set_header(entry, &block->header, prev);
}
