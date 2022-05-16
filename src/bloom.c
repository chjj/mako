/*!
 * bloom.c - bloom filters for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 *
 * Based on the bcoin code (which was based on bitcoin core).
 */

#include <math.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mako/bloom.h>
#include <mako/crypto/rand.h>
#include <mako/types.h>
#include <mako/util.h>
#include "impl.h"
#include "internal.h"

/*
 * Constants
 */

static const double BTC_LN2SQUARED =
  0.4804530139182014246671025263266649717305529515945455;

static const double BTC_LN2 =
  0.6931471805599453094172321214581765680755001343602552;

/*
 * Bloom Filter
 */

DEFINE_SERIALIZABLE_OBJECT(btc_bloom, SCOPE_EXTERN)

void
btc_bloom_init(btc_bloom_t *bloom) {
  bloom->data = NULL;
  bloom->size = 0;
  bloom->n = 0;
  bloom->tweak = 0;
  bloom->update = BTC_BLOOM_NONE;
}

void
btc_bloom_clear(btc_bloom_t *bloom) {
  if (bloom->data != NULL)
    btc_free(bloom->data);

  bloom->data = NULL;
}

void
btc_bloom_copy(btc_bloom_t *z, const btc_bloom_t *x) {
  if (x->size > 0) {
    z->data = (uint8_t *)btc_realloc(z->data, x->size);

    memcpy(z->data, x->data, x->size);
  }

  z->size = x->size;
  z->n = x->n;
  z->tweak = x->tweak;
  z->update = x->update;
}

void
btc_bloom_reset(btc_bloom_t *bloom) {
  if (bloom->size > 0)
    memset(bloom->data, 0, bloom->size);

  bloom->tweak = btc_random();
}

void
btc_bloom_set(btc_bloom_t *bloom,
              uint32_t items,
              double rate,
              uint8_t update) {
  uint32_t n, bits;

  CHECK(rate >= 0.0 && rate <= 1.0);

  bits = (uint32_t)(-1.0 / BTC_LN2SQUARED * (double)items * log(rate));

  bits -= (bits & 7);

  if (bits < 8)
    bits = 8;

  if (update != BTC_BLOOM_INTERNAL) {
    if (bits > BTC_BLOOM_MAX_BLOOM_FILTER_SIZE * 8)
      bits = BTC_BLOOM_MAX_BLOOM_FILTER_SIZE * 8;
  }

  n = (uint32_t)((double)bits / (double)items * BTC_LN2);

  if (update != BTC_BLOOM_INTERNAL) {
    if (n > BTC_BLOOM_MAX_HASH_FUNCS)
      n = BTC_BLOOM_MAX_HASH_FUNCS;
  }

  bloom->size = bits / 8;
  bloom->data = (uint8_t *)btc_realloc(bloom->data, bloom->size);
  bloom->n = n;
  bloom->update = update;

  btc_bloom_reset(bloom);
}

static size_t
btc_bloom_hash(const btc_bloom_t *bloom,
               const uint8_t *val,
               size_t len,
               uint32_t n) {
  return btc_murmur3_tweak(val, len, n, bloom->tweak) % (bloom->size * 8);
}

void
btc_bloom_add(btc_bloom_t *bloom, const uint8_t *val, size_t len) {
  uint32_t i;

  if (bloom->size == 0)
    return;

  for (i = 0; i < bloom->n; i++) {
    size_t bit = btc_bloom_hash(bloom, val, len, i);

    bloom->data[bit >> 3] |= (1 << (bit & 7));
  }
}

int
btc_bloom_has(const btc_bloom_t *bloom, const uint8_t *val, size_t len) {
  uint32_t i;

  if (bloom->size == 0)
    return 0;

  for (i = 0; i < bloom->n; i++) {
    size_t bit = btc_bloom_hash(bloom, val, len, i);

    if ((bloom->data[bit >> 3] & (1 << (bit & 7))) == 0)
      return 0;
  }

  return 1;
}

int
btc_bloom_is_within_constraints(const btc_bloom_t *bloom) {
  if (bloom->size > BTC_BLOOM_MAX_BLOOM_FILTER_SIZE)
    return 0;

  if (bloom->n > BTC_BLOOM_MAX_HASH_FUNCS)
    return 0;

  return 1;
}

size_t
btc_bloom_size(const btc_bloom_t *x) {
  return btc_size_size(x->size) + x->size + 9;
}

uint8_t *
btc_bloom_write(uint8_t *zp, const btc_bloom_t *x) {
  zp = btc_size_write(zp, x->size);
  zp = btc_raw_write(zp, x->data, x->size);
  zp = btc_uint32_write(zp, x->n);
  zp = btc_uint32_write(zp, x->tweak);
  zp = btc_uint8_write(zp, x->update);
  return zp;
}

int
btc_bloom_read(btc_bloom_t *z, const uint8_t **xp, size_t *xn) {
  const uint8_t *zp;
  size_t zn;

  if (!btc_size_read(&zn, xp, xn))
    return 0;

  if (!btc_zraw_read(&zp, zn, xp, xn))
    return 0;

  if (zn > 0) {
    z->data = (uint8_t *)btc_realloc(z->data, zn);

    memcpy(z->data, zp, zn);
  }

  z->size = zn;

  if (!btc_uint32_read(&z->n, xp, xn))
    return 0;

  if (!btc_uint32_read(&z->tweak, xp, xn))
    return 0;

  if (!btc_uint8_read(&z->update, xp, xn))
    return 0;

  return 1;
}

/*
 * Rolling Filter
 */

DEFINE_OBJECT(btc_filter, SCOPE_EXTERN)

void
btc_filter_init(btc_filter_t *filter) {
  filter->data = NULL;
  filter->length = 0;
  filter->entries = 0;
  filter->limit = 0;
  filter->generation = 1;
  filter->n = 0;
  filter->tweak = 0;
}

void
btc_filter_clear(btc_filter_t *filter) {
  if (filter->data != NULL)
    btc_free(filter->data);

  filter->data = NULL;
}

void
btc_filter_copy(btc_filter_t *z, const btc_filter_t *x) {
  if (x->length > 0) {
    z->data = (uint64_t *)btc_realloc(z->data, x->length * sizeof(uint64_t));

    memcpy(z->data, x->data, x->length * sizeof(uint64_t));
  }

  z->length = x->length;
  z->entries = x->entries;
  z->limit = x->limit;
  z->generation = x->generation;
  z->n = x->n;
  z->tweak = x->tweak;
}

void
btc_filter_reset(btc_filter_t *filter) {
  if (filter->length > 0)
    memset(filter->data, 0, filter->length * sizeof(uint64_t));

  filter->entries = 0;
  filter->generation = 1;
  filter->tweak = btc_random();
}

void
btc_filter_set(btc_filter_t *filter, uint32_t items, double rate) {
  double lograte = log(rate);
  uint32_t max, bits;
  size_t length;
  int n, limit;

  CHECK(rate >= 0.0 && rate <= 1.0);

  n = (int)((lograte / log(0.5)) + 0.5);

  if (n > 50)
    n = 50;

  if (n < 1)
    n = 1;

  limit = (items + 1) / 2;
  max = limit * 3;

  bits = (uint32_t)ceil(-1.0 * n * max / log(1.0 - exp(lograte / n)));
  length = ((bits + 63) / 64) * 2;

  if (length == 0)
    length = 2;

  filter->data = (uint64_t *)btc_realloc(filter->data,
                                         length * sizeof(uint64_t));

  filter->length = length;
  filter->limit = limit;
  filter->n = n;

  btc_filter_reset(filter);
}

static uint32_t
btc_filter_hash(const btc_filter_t *filter,
                const uint8_t *val,
                size_t len,
                uint32_t n) {
  return btc_murmur3_tweak(val, len, n, filter->tweak);
}

void
btc_filter_add(btc_filter_t *filter, const uint8_t *val, size_t len) {
  uint64_t m1, m2, p1, p2, m;
  uint32_t hash;
  size_t p, pos;
  int i, bit;

  if (filter->length == 0)
    return;

  if (filter->entries == filter->limit) {
    filter->entries = 0;
    filter->generation += 1;

    if (filter->generation == 4)
      filter->generation = 1;

    m1 = -(uint64_t)(filter->generation & 1);
    m2 = -(uint64_t)(filter->generation >> 1);

    for (p = 0; p < filter->length; p += 2) {
      p1 = filter->data[p + 0];
      p2 = filter->data[p + 1];

      m = (p1 ^ m1) | (p2 ^ m2);

      filter->data[p + 0] = p1 & m;
      filter->data[p + 1] = p2 & m;
    }
  }

  filter->entries += 1;

  for (i = 0; i < filter->n; i++) {
    hash = btc_filter_hash(filter, val, len, i);
    bit = hash & 0x3f;
    pos = (hash >> 6) % filter->length;

    filter->data[pos & ~1] &= ~(UINT64_C(1) << bit);
    filter->data[pos & ~1] |= ((uint64_t)(filter->generation & 1)) << bit;

    filter->data[pos | 1] &= ~(UINT64_C(1) << bit);
    filter->data[pos | 1] |= ((uint64_t)(filter->generation >> 1)) << bit;
  }
}

int
btc_filter_has(const btc_filter_t *filter, const uint8_t *val, size_t len) {
  uint32_t hash;
  uint64_t bits;
  size_t pos;
  int i, bit;

  if (filter->length == 0)
    return 0;

  for (i = 0; i < filter->n; i++) {
    hash = btc_filter_hash(filter, val, len, i);
    bit = hash & 0x3f;
    pos = (hash >> 6) % filter->length;
    bits = filter->data[pos & ~1] | filter->data[pos | 1];

    if (((bits >> bit) & 1) == 0)
      return 0;
  }

  return 1;
}

void
btc_filter_add_addr(btc_filter_t *filter, const btc_netaddr_t *addr) {
  uint8_t raw[18];

  btc_raw_write(raw, addr->raw, 16);
  btc_uint16_write(raw + 16, addr->port);

  btc_filter_add(filter, raw, 18);
}

int
btc_filter_has_addr(const btc_filter_t *filter, const btc_netaddr_t *addr) {
  uint8_t raw[18];

  btc_raw_write(raw, addr->raw, 16);
  btc_uint16_write(raw + 16, addr->port);

  return btc_filter_has(filter, raw, 18);
}
