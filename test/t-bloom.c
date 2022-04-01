/*!
 * t-bloom.c - bloom filter test for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mako/bloom.h>
#include "lib/tests.h"

/*
 * Helpers
 */

static void
btc_bloom_init_ex(btc_bloom_t *bloom, size_t size, int n, uint32_t tweak) {
  if (size > 0) {
    bloom->data = malloc(size);

    ASSERT(bloom->data != NULL);

    memset(bloom->data, 0, size);
  } else {
    bloom->data = NULL;
  }

  bloom->size = size;
  bloom->n = n;
  bloom->tweak = tweak;
  bloom->update = BTC_BLOOM_NONE;
}

#define btc_bloom_add_str(bloom, str) \
  btc_bloom_add(bloom, (uint8_t *)str, strlen(str))

#define btc_bloom_has_str(bloom, str) \
  btc_bloom_has(bloom, (const uint8_t *)str, strlen(str))

/*
 * Bloom Tests
 */

static void
test_bloom1(void) {
  btc_bloom_t bloom;

  btc_bloom_init_ex(&bloom, 512 / 8, 10, 156);

  btc_bloom_add_str(&bloom, "hello");

  ASSERT(btc_bloom_has_str(&bloom, "hello"));
  ASSERT(!btc_bloom_has_str(&bloom, "hello!"));
  ASSERT(!btc_bloom_has_str(&bloom, "ping"));

  btc_bloom_add_str(&bloom, "hello!");

  ASSERT(btc_bloom_has_str(&bloom, "hello!"));
  ASSERT(!btc_bloom_has_str(&bloom, "ping"));

  btc_bloom_add_str(&bloom, "ping");

  ASSERT(btc_bloom_has_str(&bloom, "ping"));

  btc_bloom_clear(&bloom);
}

static void
test_bloom2(void) {
  static const uint8_t item1[] = {
    0x8e, 0x74, 0x45, 0xbb, 0xb8, 0xab, 0xd4, 0xb3,
    0x17, 0x4d, 0x80, 0xfa, 0x4c, 0x40, 0x9f, 0xea,
    0x6b, 0x94, 0xd9, 0x6b
  };

  static const uint8_t item2[] = {
    0x04, 0x7b, 0x00, 0x00, 0x00, 0x78, 0xda, 0x0d,
    0xca, 0x3b, 0x0e, 0xc2, 0x30, 0x0c, 0x00, 0xd0,
    0xab, 0x44, 0x66, 0xed, 0x10, 0xe7, 0x63, 0x27,
    0x2c, 0x6c, 0x9c, 0xa0, 0x52, 0x97, 0x2c, 0x69,
    0xe3, 0x88, 0x4a, 0x90, 0x22, 0x08, 0x42, 0x15,
    0xe2, 0xee, 0xf0, 0xe6, 0xf7, 0x81, 0x65, 0x6b,
    0x5d, 0x5a, 0x87, 0x23, 0x1c, 0xd4, 0x34, 0x9e,
    0x53, 0x4b, 0x6d, 0xea, 0x55, 0xad, 0x4f, 0xf5,
    0x5e
  };

  static const uint8_t expect[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x80, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x08,
    0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00
  };

  btc_bloom_t bloom;

  btc_bloom_init_ex(&bloom, 952 / 8, 6, UINT32_C(3624314491));
  btc_bloom_add(&bloom, item1, sizeof(item1));
  btc_bloom_add(&bloom, item2, sizeof(item2));

  ASSERT(bloom.size == sizeof(expect));
  ASSERT(memcmp(bloom.data, expect, sizeof(expect)) == 0);

  btc_bloom_clear(&bloom);
}

static void
test_bloom3(void) {
  btc_bloom_t bloom;
  uint64_t j, k;
  int i;

  btc_bloom_init(&bloom);
  btc_bloom_set(&bloom, 210000, 0.00001, BTC_BLOOM_INTERNAL);

  bloom.tweak = 0xdeadbeef;

  /* 1m operations */
  for (i = 0; i < 1000; i++) {
    j = i;

    btc_bloom_add(&bloom, (uint8_t *)&j, sizeof(j));

    do {
      ASSERT(btc_bloom_has(&bloom, (uint8_t *)&j, sizeof(j)));
      k = ~j;
      ASSERT(!btc_bloom_has(&bloom, (uint8_t *)&k, sizeof(k)));
    } while (j--);
  }

  btc_bloom_clear(&bloom);
}

/*
 * Rolling Filter Tests
 */

static void
test_filter1(void) {
  btc_filter_t filter;
  uint64_t j, k;
  int i;

  btc_filter_init(&filter);
  btc_filter_set(&filter, 210000, 0.00001);

  filter.tweak = 0xdeadbeef;

  /* 1m operations */
  for (i = 0; i < 1000; i++) {
    j = i;

    btc_filter_add(&filter, (uint8_t *)&j, sizeof(j));

    do {
      ASSERT(btc_filter_has(&filter, (uint8_t *)&j, sizeof(j)));
      k = ~j;
      ASSERT(!btc_filter_has(&filter, (uint8_t *)&k, sizeof(k)));
    } while (j--);
  }

  btc_filter_clear(&filter);
}

static void
test_filter2(void) {
  btc_filter_t filter;
  uint64_t j, k;
  int i;

  btc_filter_init(&filter);
  btc_filter_set(&filter, 50, 0.00001);

  filter.tweak = 0xdeadbeee;

  for (i = 0; i < 75; i++) {
    j = i;

    btc_filter_add(&filter, (uint8_t *)&j, sizeof(j));

    do {
      ASSERT(btc_filter_has(&filter, (uint8_t *)&j, sizeof(j)));
      k = ~j;
      ASSERT(!btc_filter_has(&filter, (uint8_t *)&k, sizeof(k)));
    } while (j--);
  }

  for (i = 75; i < 100; i++) {
    j = i;

    btc_filter_add(&filter, (uint8_t *)&j, sizeof(j));

    do {
      ASSERT(btc_filter_has(&filter, (uint8_t *)&j, sizeof(j)));
      k = ~j;
      ASSERT(!btc_filter_has(&filter, (uint8_t *)&k, sizeof(k)));
    } while (j-- > 25);

    ASSERT(!btc_filter_has(&filter, (uint8_t *)&j, sizeof(j)));
  }

  for (i = 100; i < 125; i++) {
    j = i;

    btc_filter_add(&filter, (uint8_t *)&j, sizeof(j));

    do {
      ASSERT(btc_filter_has(&filter, (uint8_t *)&j, sizeof(j)));
      k = ~j;
      ASSERT(!btc_filter_has(&filter, (uint8_t *)&k, sizeof(k)));
    } while (j-- > 50);

    ASSERT(!btc_filter_has(&filter, (uint8_t *)&j, sizeof(j)));
  }

  btc_filter_clear(&filter);
}

/*
 * Main
 */

int
main(void) {
  test_bloom1();
  test_bloom2();
  test_bloom3();
  test_filter1();
  test_filter2();
  return 0;
}
