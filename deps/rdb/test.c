/*!
 * test.c - rdb tests
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#include "rdb.h"

/*
 * Macros
 */

#define CHECK(x) do { if (!(x)) abort(); } while (0)

/*
 * Helpers
 */

static void *
rdb_malloc(size_t size) {
  void *ptr = malloc(size);

  if (ptr == NULL)
    abort();

  return ptr;
}

static void
rdb_free(void *ptr) {
  free(ptr);
}

static uint8_t *
rdb_uint32_write(uint8_t *zp, uint32_t x) {
  *zp++ = (x >>  0);
  *zp++ = (x >>  8);
  *zp++ = (x >> 16);
  *zp++ = (x >> 24);
  return zp;
}

static int64_t
time_msec(void) {
#ifdef _WIN32
  static const uint64_t epoch = UINT64_C(116444736000000000);
  ULARGE_INTEGER ul;
  FILETIME ft;

  GetSystemTimeAsFileTime(&ft);

  ul.LowPart = ft.dwLowDateTime;
  ul.HighPart = ft.dwHighDateTime;

  return (ul.QuadPart - epoch) / 10000;
#else
  struct timeval tv;

  CHECK(gettimeofday(&tv, NULL) == 0);

  return ((int64_t)tv.tv_sec * 1000) + (tv.tv_usec / 1000);
#endif
}

static uint32_t
hash32(uint32_t x) {
  x = (x + 0x7ed55d16) + (x << 12);
  x = (x ^ 0xc761c23c) ^ (x >> 19);
  x = (x + 0x165667b1) + (x << 5);
  x = (x + 0xd3a2646c) ^ (x << 9);
  x = (x + 0xfd7046c5) + (x << 3);
  x = (x ^ 0xb55a4f09) ^ (x >> 16);
  return x;
}

#ifdef _WIN32
#define unlink rdb__unlink
static int
unlink(const char *name) {
  if (!DeleteFileA(name))
    return -1;
  return 0;
}
#endif

/*
 * Testing
 */

static int
rdb_test_main(void) {
  const uint8_t *out = NULL;
  uint8_t val[128];
  uint8_t key[37];
  rdb_txn_t *tx;
  size_t len;
  rdb_t *db;
  int i;

  unlink("tmp.dat");

  for (i = 0; i < 37; i++)
    key[i] = i;

  for (i = 0; i < 128; i++)
    val[i] = i;

  db = rdb_create();

  CHECK(rdb_open(db, "tmp.dat", RDB_RDWR | RDB_CREATE, 0644) == 0);

  tx = rdb_txn_create(db);

  for (i = 0; i < 100000; i++) {
    rdb_uint32_write(key, hash32(i));
    rdb_uint32_write(val, hash32(i));

    CHECK(rdb_txn_put(tx, key, 37, val, 128) == 0);
    CHECK(rdb_txn_get(tx, &out, &len, key, 37) == 0);
    CHECK(len == 128);
    CHECK(memcmp(val, out, len) == 0);
  }

  CHECK(rdb_txn_commit(tx) == 0);

  for (i = 0; i < 100000; i++) {
    rdb_uint32_write(key, hash32(i));
    rdb_uint32_write(val, hash32(i));

    CHECK(rdb_txn_get(tx, &out, &len, key, 37) == 0);
    CHECK(len == 128);
    CHECK(memcmp(val, out, len) == 0);
  }

  rdb_txn_destroy(tx);
  CHECK(rdb_close(db) == RDB_OK);
  rdb_destroy(db);

  {
    db = rdb_create();

    CHECK(rdb_open(db, "tmp.dat", RDB_RDWR, 0) == 0);

    tx = rdb_txn_create(db);

    for (i = 0; i < 100000; i++) {
      rdb_uint32_write(key, hash32(i));
      rdb_uint32_write(val, hash32(i));

      CHECK(rdb_txn_get(tx, &out, &len, key, 37) == 0);
      CHECK(len == 128);
      CHECK(memcmp(val, out, len) == 0);
    }

    for (i = 0; i < 100000; i += 2) {
      rdb_uint32_write(key, hash32(i));
      rdb_uint32_write(val, hash32(i));

      CHECK(rdb_txn_del(tx, key, 37) == 0);
      CHECK(rdb_txn_get(tx, &out, &len, key, 37) == RDB_ENOTFOUND);
    }

    CHECK(rdb_txn_commit(tx) == 0);

    for (i = 0; i < 100000; i += 2) {
      rdb_uint32_write(key, hash32(i));
      rdb_uint32_write(val, hash32(i));

      CHECK(rdb_txn_get(tx, &out, &len, key, 37) == RDB_ENOTFOUND);
    }

    rdb_txn_destroy(tx);
    CHECK(rdb_close(db) == RDB_OK);
    rdb_destroy(db);
  }

  {
    db = rdb_create();

    CHECK(rdb_open(db, "tmp.dat", RDB_RDWR, 0) == 0);

    tx = rdb_txn_create(db);

    for (i = 0; i < 100000; i++) {
      rdb_uint32_write(key, hash32(i));
      rdb_uint32_write(val, hash32(i));

      if (i & 1) {
        CHECK(rdb_txn_get(tx, &out, &len, key, 37) == 0);
        CHECK(len == 128);
        CHECK(memcmp(val, out, len) == 0);
      } else {
        CHECK(rdb_txn_get(tx, &out, &len, key, 37) == RDB_ENOTFOUND);
      }
    }

    rdb_compact(db);

    for (i = 0; i < 100000; i++) {
      rdb_uint32_write(key, hash32(i));
      rdb_uint32_write(val, hash32(i));

      if (i & 1) {
        CHECK(rdb_txn_get(tx, &out, &len, key, 37) == 0);
        CHECK(len == 128);
        CHECK(memcmp(val, out, len) == 0);
      } else {
        CHECK(rdb_txn_get(tx, &out, &len, key, 37) == RDB_ENOTFOUND);
      }
    }

    rdb_txn_destroy(tx);

    CHECK(rdb_close(db) == RDB_OK);
    rdb_destroy(db);
  }

  {
    db = rdb_create();

    CHECK(rdb_open(db, "tmp.dat", RDB_RDWR, 0) == 0);

    tx = rdb_txn_create(db);

    for (i = 0; i < 100000; i++) {
      rdb_uint32_write(key, hash32(i));
      rdb_uint32_write(val, hash32(i));

      if (i & 1) {
        CHECK(rdb_txn_get(tx, &out, &len, key, 37) == 0);
        CHECK(len == 128);
        CHECK(memcmp(val, out, len) == 0);
      } else {
        CHECK(rdb_txn_get(tx, &out, &len, key, 37) == RDB_ENOTFOUND);
      }
    }

    rdb_txn_destroy(tx);
    CHECK(rdb_close(db) == RDB_OK);
    rdb_destroy(db);
  }

  CHECK(unlink("tmp.dat") == 0);
#ifndef RDB_TLS
  CHECK(rdb_memusage() == 0);
#endif

  return 0;
}

static int
rdb_test_iter(void) {
  uint8_t min[37], max[37];
  uint8_t **keys, **vals;
  const uint8_t *kp, *vp;
  int i, j, k, rc;
  rdb_iter_t *it;
  size_t kn, vn;
  rdb_txn_t *tx;
  rdb_t *db;

  unlink("tmp.dat");

  keys = rdb_malloc(26 * 100 * sizeof(uint8_t *));
  vals = rdb_malloc(26 * 100 * sizeof(uint8_t *));

  for (i = 0; i < 26; i++) {
    for (j = 0; j < 100; j++) {
      uint8_t *key = rdb_malloc(37);
      uint8_t *val = rdb_malloc(128);

      key[0] = 'a' + i;

      for (k = 1; k < 37; k++)
        key[k] = j + k;

      for (k = 0; k < 128; k++)
        val[k] = rand();

      keys[i * 100 + j] = key;
      vals[i * 100 + j] = val;
    }
  }

  db = rdb_create();

  CHECK(rdb_open(db, "tmp.dat", RDB_RDWR | RDB_CREATE, 0644) == 0);

  tx = rdb_txn_create(db);

  for (i = 0; i < 26 * 100; i++)
    CHECK(rdb_txn_put(tx, keys[i], 37, vals[i], 128) == 0);

  CHECK(rdb_txn_commit(tx) == 0);

  it = rdb_iter_create(tx);

  memset(min, 0, 37);
  memset(max, 0xff, 37);

  min[0] = 'k';
  max[0] = 'k';

  rc = rdb_iter_seek(it, min, 37);
  i = ('k' - 'a') * 100;
  j = 0;

  while (rc == RDB_OK) {
    CHECK(rdb_iter_key(it, &kp, &kn) == 0);

    if (memcmp(kp, max, 37) > 0)
      break;

    CHECK(kn == 37);
    CHECK(memcmp(kp, keys[i], 37) == 0);

    CHECK(rdb_iter_value(it, &vp, &vn) == 0);
    CHECK(vn == 128);
    CHECK(memcmp(vp, vals[i], 128) == 0);

    rc = rdb_iter_next(it);
    i += 1;
    j += 1;
  }

  CHECK(rc == RDB_OK);
  CHECK(j == 100);

  rc = rdb_iter_first(it);
  i = 0;

  while (rc == RDB_OK) {
    CHECK(rdb_iter_key(it, &kp, &kn) == 0);
    CHECK(kn == 37);
    CHECK(memcmp(kp, keys[i], 37) == 0);

    CHECK(rdb_iter_value(it, &vp, &vn) == 0);
    CHECK(vn == 128);
    CHECK(memcmp(vp, vals[i], 128) == 0);

    rc = rdb_iter_next(it);
    i += 1;
  }

  CHECK(rc == RDB_ENOTFOUND);
  CHECK(i == 26 * 100);

  rdb_iter_destroy(it);
  rdb_txn_destroy(tx);
  CHECK(rdb_close(db) == RDB_OK);
  rdb_destroy(db);

  CHECK(unlink("tmp.dat") == 0);
#ifndef RDB_TLS
  CHECK(rdb_memusage() == 0);
#endif

  for (i = 0; i < 26 * 100; i++) {
    rdb_free(keys[i]);
    rdb_free(vals[i]);
  }

  rdb_free(keys);
  rdb_free(vals);

  return 0;
}

/*
 * Benchmarks
 */

static int
rdb_bench(int iter) {
  const uint8_t *out = NULL;
  uint8_t **keys, **vals;
  rdb_txn_t *tx;
  int64_t now;
  size_t len;
  rdb_t *db;
  int i, j;

  printf("iterations: %d\n", iter);

  keys = rdb_malloc(iter * sizeof(uint8_t *));
  vals = rdb_malloc(iter * sizeof(uint8_t *));

  for (i = 0; i < iter; i++) {
    uint8_t *key = rdb_malloc(37);
    uint8_t *val = rdb_malloc(128);

    for (j = 0; j < 37; j++)
      key[j] = rand();

    for (j = 0; j < 128; j++)
      val[j] = rand();

    keys[i] = key;
    vals[i] = val;
  }

  db = rdb_create();

  CHECK(rdb_open(db, "tmp.dat", RDB_RDWR | RDB_CREATE, 0644) == 0);

  tx = rdb_txn_create(db);

  now = time_msec();

  for (i = 0; i < iter; i++)
    CHECK(rdb_txn_put(tx, keys[i], 37, vals[i], 128) == 0);

  printf("put: %.3fs\n", (double)(time_msec() - now) / 1000.0);

  now = time_msec();

  for (i = 0; i < iter; i++) {
    CHECK(rdb_txn_get(tx, &out, &len, keys[i], 37) == 0);
    CHECK(len == 128);
    CHECK(memcmp(vals[i], out, len) == 0);
  }

  printf("get cached: %.3fs\n", (double)(time_msec() - now) / 1000.0);

  now = time_msec();

  CHECK(rdb_txn_commit(tx) == 0);

  printf("commit: %.3fs\n", (double)(time_msec() - now) / 1000.0);

  now = time_msec();

  for (i = 0; i < iter; i++) {
    CHECK(rdb_txn_get(tx, &out, &len, keys[i], 37) == 0);
    CHECK(len == 128);
    CHECK(memcmp(vals[i], out, len) == 0);
  }

  printf("get uncached: %.3fs\n", (double)(time_msec() - now) / 1000.0);

  rdb_txn_destroy(tx);
  CHECK(rdb_close(db) == RDB_OK);
  rdb_destroy(db);

#ifndef RDB_TLS
  CHECK(rdb_memusage() == 0);
#endif

  for (i = 0; i < iter; i++) {
    rdb_free(keys[i]);
    rdb_free(vals[i]);
  }

  rdb_free(keys);
  rdb_free(vals);

  return 0;
}

int
main(int argc, char **argv) {
  if (argc < 2) {
    rdb_test_main();
    rdb_test_iter();
    return 0;
  }

  return rdb_bench(atoi(argv[1]));
}
