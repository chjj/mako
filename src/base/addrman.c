/*!
 * addrman.c - address manager for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 *
 * Logic based on both Bitcoin Core and btcd.
 */

#include <math.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <io/core.h>

#include <base/addrman.h>
#include <base/logger.h>
#include <base/timedata.h>

#include <mako/crypto/hash.h>
#include <mako/crypto/rand.h>
#include <mako/list.h>
#include <mako/map.h>
#include <mako/net.h>
#include <mako/netaddr.h>
#include <mako/network.h>
#include <mako/util.h>
#include <mako/vector.h>

#include "../bio.h"
#include "../impl.h"
#include "../internal.h"

/*
 * Constants
 */

#define SER_VERSION 0
#define HORIZON_DAYS 30
#define MAX_RETRIES 3
#define MIN_FAIL_DAYS 7
#define MAX_FAILURES 10
#define MAX_REFS 8
#define FRESH_COUNT 1024
#define FRESH_SIZE 64
#define FRESH_SPREAD 64
#define USED_COUNT 64
#define USED_SIZE 256
#define USED_SPREAD 8

/*
 * Address Key
 */

#define BTC_ADDRKEY_SIZE 18

static uint8_t *
btc_addrkey_write(uint8_t *zp, const btc_netaddr_t *x) {
  zp = btc_raw_write(zp, x->raw, 16);
  zp = btc_uint16_write(zp, x->port);
  return zp;
}

static int
btc_addrkey_read(btc_netaddr_t *z, const uint8_t **xp, size_t *xn) {
  uint16_t port;

  btc_netaddr_init(z);

  if (!btc_raw_read(z->raw, 16, xp, xn))
    return 0;

  if (!btc_uint16_read(&port, xp, xn))
    return 0;

  z->port = port;

  return 1;
}

/*
 * Address Entry
 */

#define BTC_ADDRENT_SIZE (2 * BTC_ADDRKEY_SIZE + 36)

DEFINE_OBJECT(btc_addrent, SCOPE_STATIC)

static void
btc_addrent_init(btc_addrent_t *entry) {
  btc_netaddr_init(&entry->addr);
  btc_netaddr_init(&entry->src);
  entry->used = 0;
  entry->ref_count = 0;
  entry->attempts = 0;
  entry->last_success = 0;
  entry->last_attempt = 0;
  entry->rand_pos = 0;
  entry->prev = NULL;
  entry->next = NULL;
}

static void
btc_addrent_clear(btc_addrent_t *entry) {
  btc_netaddr_clear(&entry->addr);
  btc_netaddr_clear(&entry->src);
}

static void
btc_addrent_copy(btc_addrent_t *z, const btc_addrent_t *x) {
  btc_netaddr_copy(&z->addr, &x->addr);
  btc_netaddr_copy(&z->src, &x->src);
  z->used = x->used;
  z->ref_count = x->ref_count;
  z->attempts = x->attempts;
  z->last_success = x->last_success;
  z->last_attempt = x->last_attempt;
  z->rand_pos = x->rand_pos;
  z->prev = x->prev;
  z->next = x->next;
}

static double
btc_addrent_chance(const btc_addrent_t *entry, int64_t now) {
  double attempts = entry->attempts;
  double c = 1;

  if (attempts > 8)
    attempts = 8;

  if (now - entry->last_attempt < 60 * 10)
    c *= 0.01;

  c *= pow(0.66, attempts);

  return c;
}

static int
btc_addrent_is_stale(const btc_addrent_t *entry, int64_t now) {
  if (entry->last_attempt && entry->last_attempt >= now - 60)
    return 0;

  if (entry->addr.time > now + 10 * 60)
    return 1;

  if (entry->addr.time == 0)
    return 1;

  if (now - entry->addr.time > HORIZON_DAYS * 24 * 60 * 60)
    return 1;

  if (entry->last_success == 0 && entry->attempts >= MAX_RETRIES)
    return 1;

  if (now - entry->last_success > MIN_FAIL_DAYS * 24 * 60 * 60) {
    if (entry->attempts >= MAX_FAILURES)
      return 1;
  }

  return 0;
}

static uint8_t *
btc_addrent_write(uint8_t *zp, const btc_addrent_t *x) {
  zp = btc_addrkey_write(zp, &x->addr);
  zp = btc_uint64_write(zp, x->addr.services);
  zp = btc_int64_write(zp, x->addr.time);
  zp = btc_addrkey_write(zp, &x->src);
  zp = btc_int32_write(zp, x->attempts);
  zp = btc_int64_write(zp, x->last_success);
  zp = btc_int64_write(zp, x->last_attempt);
  return zp;
}

static int
btc_addrent_read(btc_addrent_t *z, const uint8_t **xp, size_t *xn) {
  if (!btc_addrkey_read(&z->addr, xp, xn))
    return 0;

  if (!btc_uint64_read(&z->addr.services, xp, xn))
    return 0;

  if (!btc_int64_read(&z->addr.time, xp, xn))
    return 0;

  if (!btc_addrkey_read(&z->src, xp, xn))
    return 0;

  z->src.services = BTC_NET_DEFAULT_SERVICES;
  z->src.time = btc_now();

  z->used = 0;
  z->ref_count = 0;

  if (!btc_int32_read(&z->attempts, xp, xn))
    return 0;

  if (!btc_int64_read(&z->last_success, xp, xn))
    return 0;

  if (!btc_int64_read(&z->last_attempt, xp, xn))
    return 0;

  z->rand_pos = 0;
  z->prev = NULL;
  z->next = NULL;

  return 1;
}

/*
 * Used Bucket
 */

typedef struct btc_bucket_s {
  btc_addrent_t *head;
  btc_addrent_t *tail;
  size_t length;
} btc_bucket_t;

/*
 * Local Address
 */

typedef struct btc_local_s {
  btc_netaddr_t addr;
  int type;
  int score;
} btc_local_t;

DEFINE_OBJECT(btc_local, SCOPE_STATIC)

static void
btc_local_init(btc_local_t *entry) {
  btc_netaddr_init(&entry->addr);
  entry->type = 0;
  entry->score = 0;
}

static void
btc_local_clear(btc_local_t *entry) {
  btc_netaddr_clear(&entry->addr);
}

static void
btc_local_copy(btc_local_t *z, const btc_local_t *x) {
  btc_netaddr_copy(&z->addr, &x->addr);
  z->type = x->type;
  z->score = x->score;
}

/*
 * Randomly Sorted Vector
 */

static void
btc_randvec_push(btc_vector_t *rnd, btc_addrent_t *entry) {
  entry->rand_pos = rnd->length;
  btc_vector_push(rnd, entry);
}

static void
btc_randvec_pop(btc_vector_t *rnd, btc_addrent_t *entry) {
  btc_addrent_t *top = btc_vector_pop(rnd);

  if (top == entry)
    return;

  rnd->items[entry->rand_pos] = top;

  top->rand_pos = entry->rand_pos;
}

static btc_addrent_t *
btc_randvec_swap(btc_vector_t *rnd, size_t i, size_t j) {
  btc_addrent_t *x = rnd->items[i];
  btc_addrent_t *y = rnd->items[j];

  rnd->items[j] = x;
  rnd->items[i] = y;

  x->rand_pos = j;
  y->rand_pos = i;

  return y;
}

/*
 * Address Manager
 */

struct btc_addrman_s {
  const btc_network_t *network;
  btc_logger_t *logger;
  const btc_timedata_t *timedata;
  char file[BTC_PATH_MAX];
  unsigned int flags;
  btc_netaddr_t addr;
  btc_sockaddr_t proxy;
  int64_t ban_time;
  uint8_t key[32];
  btc_netmap_t map;
  btc_vector_t rnd;
  btc_netmap_t *fresh;
  size_t total_fresh;
  btc_bucket_t *used;
  size_t total_used;
  btc_netmap_t local;
  btc_netmap_t banned;
  int needs_flush;
};

BTC_DEFINE_LOGGER(btc_log, btc_addrman_t, "addrman")

btc_addrman_t *
btc_addrman_create(const btc_network_t *network) {
  btc_addrman_t *man = btc_malloc(sizeof(btc_addrman_t));
  int i;

  memset(man, 0, sizeof(*man));

  man->network = network;
  man->logger = NULL;
  man->timedata = NULL;
  man->file[0] = '\0';
  man->flags = 0;
  btc_netaddr_set(&man->addr, "127.0.0.1", network->port);
  man->addr.services = BTC_NET_DEFAULT_SERVICES;
  man->addr.time = btc_now();
  btc_sockaddr_import(&man->proxy, "0.0.0.0", 0);
  man->ban_time = 24 * 60 * 60;
  btc_getrandom(man->key, 32);
  btc_netmap_init(&man->map);
  btc_vector_init(&man->rnd);
  man->fresh = btc_malloc(FRESH_COUNT * sizeof(btc_netmap_t));
  man->total_fresh = 0;
  man->used = btc_malloc(USED_COUNT * sizeof(btc_bucket_t));
  man->total_used = 0;
  btc_netmap_init(&man->local);
  btc_netmap_init(&man->banned);
  man->needs_flush = 0;

  for (i = 0; i < FRESH_COUNT; i++)
    btc_netmap_init(&man->fresh[i]);

  for (i = 0; i < USED_COUNT; i++)
    btc_list_init(&man->used[i]);

  return man;
}

void
btc_addrman_destroy(btc_addrman_t *man) {
  btc_mapiter_t it;
  size_t i;

  btc_map_each(&man->map, it)
    btc_addrent_destroy(man->map.vals[it]);

  for (i = 0; i < FRESH_COUNT; i++)
    btc_netmap_clear(&man->fresh[i]);

  for (i = 0; i < USED_COUNT; i++)
    btc_list_reset(&man->used[i]);

  btc_map_each(&man->local, it)
    btc_local_destroy(man->local.vals[it]);

  btc_map_each(&man->banned, it)
    btc_netaddr_destroy(man->banned.vals[it]);

  btc_netmap_clear(&man->map);
  btc_vector_clear(&man->rnd);
  btc_free(man->fresh);
  btc_free(man->used);
  btc_netmap_clear(&man->local);
  btc_netmap_clear(&man->banned);
  btc_free(man);
}

void
btc_addrman_set_logger(btc_addrman_t *man, btc_logger_t *logger) {
  man->logger = logger;
}

void
btc_addrman_set_timedata(btc_addrman_t *man, const btc_timedata_t *td) {
  man->timedata = td;
}

void
btc_addrman_set_proxy(btc_addrman_t *man, const btc_netaddr_t *addr) {
  btc_netaddr_get_sockaddr(&man->proxy, addr);
}

void
btc_addrman_set_bantime(btc_addrman_t *man, int64_t ban_time) {
  man->ban_time = ban_time;
}

static int
btc_addrman_read_file(btc_addrman_t *man, const char *file) {
  uint8_t *xp;
  size_t xn;

  if (!btc_fs_read_file(file, &xp, &xn))
    return 0;

  if (!btc_addrman_import(man, xp, xn)) {
    btc_free(xp);
    return 0;
  }

  btc_free(xp);

  return 1;
}

static int
btc_addrman_resolve(btc_addrman_t *man) {
  const btc_network_t *network = man->network;
  int64_t now = btc_now();
  btc_sockaddr_t *res, *it;
  btc_netaddr_t addr;
  size_t i;

  for (i = 0; i < network->seeds.length; i++) {
    const char *seed = network->seeds.items[i];

    if (btc_netaddr_set_str(&addr, seed)) {
      addr.time = now;
      addr.services = BTC_NET_DEFAULT_SERVICES;

      if (addr.port == 0)
        addr.port = network->port;

      btc_addrman_add(man, &addr, NULL);

      continue;
    }

    /* Temporary. */
    if (man->map.size >= 10)
      continue;

    btc_log_info(man, "Resolving %s...", seed);

    if (btc_getaddrinfo(&res, seed, network->port)) {
      int total = 0;

      for (it = res; it != NULL; it = it->next) {
        btc_netaddr_set_sockaddr(&addr, it);

        addr.time = now;
        addr.services = BTC_NET_DEFAULT_SERVICES;

        btc_addrman_add(man, &addr, NULL);

        total += 1;
      }

      btc_log_info(man, "Resolved %d seeds from %s", total, seed);

      btc_freeaddrinfo(res);
    } else {
      btc_log_info(man, "Could not resolve %s", seed);
    }
  }

  btc_log_info(man, "Resolved %zu seeds.", btc_addrman_total(man));

  return btc_addrman_total(man) > 0;
}

int
btc_addrman_open(btc_addrman_t *man, const char *file, unsigned int flags) {
  man->flags = flags;

  if (file != NULL) {
    if (!btc_strcpy(man->file, sizeof(man->file), file))
      return 0;

    if (btc_addrman_read_file(man, man->file))
      return 1;

    btc_log_warn(man, "Could not read %s.", man->file);
  } else {
    man->file[0] = '\0';
  }

  return btc_addrman_resolve(man);
}

void
btc_addrman_close(btc_addrman_t *man) {
  btc_addrman_reset(man);
}

static int
btc_addrman_write_file(btc_addrman_t *man, const char *file) {
  size_t zn = btc_addrman_size(man);
  uint8_t *zp = btc_malloc(zn);
  int ret;

  CHECK(btc_addrman_export(zp, man) == zn);

  ret = btc_fs_write_file(file, zp, zn);

  btc_free(zp);

  return ret;
}

void
btc_addrman_flush(btc_addrman_t *man) {
  if (man->needs_flush && *man->file) {
    btc_log_debug(man, "Flushing %zu addresses to disk.",
                       btc_addrman_total(man));

    if (!btc_addrman_write_file(man, man->file)) {
      btc_log_warn(man, "Could not write %s.", man->file);
      return;
    }

    man->needs_flush = 0;
  }
}

size_t
btc_addrman_total(btc_addrman_t *man) {
  return man->total_fresh + man->total_used;
}

int
btc_addrman_is_full(btc_addrman_t *man) {
  return man->total_fresh >= FRESH_COUNT * FRESH_SIZE;
}

void
btc_addrman_reset(btc_addrman_t *man) {
  btc_mapiter_t it;
  size_t i;

  btc_map_each(&man->map, it)
    btc_addrent_destroy(man->map.vals[it]);

  btc_netmap_reset(&man->map);
  btc_vector_reset(&man->rnd);

  for (i = 0; i < FRESH_COUNT; i++)
    btc_netmap_reset(&man->fresh[i]);

  for (i = 0; i < USED_COUNT; i++)
    btc_list_reset(&man->used[i]);

  man->total_fresh = 0;
  man->total_used = 0;

  btc_getrandom(man->key, 32);
}

void
btc_addrman_ban(btc_addrman_t *man, const btc_netaddr_t *addr) {
  btc_netaddr_t *entry = btc_netaddr_clone(addr);

  entry->port = 0;
  entry->time = btc_now();

  if (!btc_netmap_put(&man->banned, entry, entry))
    btc_netaddr_destroy(entry);
}

void
btc_addrman_unban(btc_addrman_t *man, const btc_netaddr_t *addr) {
  btc_netaddr_t key = *addr;

  key.port = 0;

  btc_netmap_del(&man->banned, &key);
}

int
btc_addrman_is_banned(btc_addrman_t *man, const btc_netaddr_t *addr) {
  btc_netaddr_t key = *addr;
  btc_netaddr_t *entry;

  key.port = 0;

  entry = btc_netmap_get(&man->banned, &key);

  if (entry == NULL)
    return 0;

  if (btc_now() > entry->time + man->ban_time) {
    btc_netmap_del(&man->banned, &key);
    btc_netaddr_destroy(entry);
    return 0;
  }

  return 1;
}

void
btc_addrman_clear_banned(btc_addrman_t *man) {
  btc_mapiter_t it;

  btc_map_each(&man->banned, it)
    btc_netaddr_destroy(man->banned.vals[it]);

  btc_netmap_reset(&man->banned);
}

const btc_addrent_t *
btc_addrman_get(btc_addrman_t *man) {
  btc_addrent_t *entry = NULL;
  double factor, num;
  int used = -1;
  size_t index;
  int64_t now;

  if (man->total_fresh > 0)
    used = 0;

  if (man->total_used > 0) {
    if (man->total_fresh == 0 || btc_uniform(2) == 0)
      used = 1;
  }

  if (used == -1)
    return NULL;

  now = btc_timedata_now(man->timedata);
  factor = 1.0;

  for (;;) {
    if (used) {
      size_t i = btc_uniform(USED_COUNT);
      btc_bucket_t *bucket = &man->used[i];

      if (bucket->length == 0)
        continue;

      index = btc_uniform(bucket->length);
      entry = bucket->head;

      while (index--)
        entry = entry->next;
    } else {
      size_t i = btc_uniform(FRESH_COUNT);
      btc_netmap_t *bucket = &man->fresh[i];
      btc_mapiter_t it;

      if (bucket->size == 0)
        continue;

      index = btc_uniform(bucket->size);

      btc_map_each(bucket, it) {
        entry = bucket->vals[it];

        if (index == 0)
          break;

        index -= 1;
      }
    }

    num = btc_uniform(1U << 30);

    if (num < factor * btc_addrent_chance(entry, now) * (double)(1U << 30))
      break;

    factor *= 1.2;
  }

  return entry;
}

static btc_netmap_t *
fresh_bucket(btc_addrman_t *man, const btc_addrent_t *entry) {
  uint32_t hash32, hash, index;
  uint8_t hash1[32];
  uint8_t hash2[32];
  btc_hash256_t ctx;
  uint8_t tmp[6];

  btc_hash256_init(&ctx);
  btc_hash256_update(&ctx, man->key, 32);
  btc_hash256_update(&ctx, btc_netaddr_groupkey(tmp, &entry->addr), 6);
  btc_hash256_update(&ctx, btc_netaddr_groupkey(tmp, &entry->src), 6);
  btc_hash256_final(&ctx, hash1);

  hash32 = btc_read32le(hash1) % FRESH_SPREAD;

  btc_hash256_init(&ctx);
  btc_hash256_update(&ctx, man->key, 32);
  btc_hash256_update(&ctx, btc_netaddr_groupkey(tmp, &entry->src), 6);
  btc_uint32_update(&ctx, hash32);
  btc_hash256_final(&ctx, hash2);

  hash = btc_read32le(hash2);
  index = hash % FRESH_COUNT;

  return &man->fresh[index];
}

static btc_bucket_t *
used_bucket(btc_addrman_t *man, const btc_addrent_t *entry) {
  uint32_t hash32, hash, index;
  uint8_t hash1[32];
  uint8_t hash2[32];
  btc_hash256_t ctx;
  uint8_t tmp[6];

  btc_hash256_init(&ctx);
  btc_hash256_update(&ctx, man->key, 32);
  btc_hash256_update(&ctx, entry->addr.raw, 16);
  btc_uint16_update(&ctx, entry->addr.port);
  btc_hash256_final(&ctx, hash1);

  hash32 = btc_read32le(hash1) % USED_SPREAD;

  btc_hash256_init(&ctx);
  btc_hash256_update(&ctx, man->key, 32);
  btc_hash256_update(&ctx, btc_netaddr_groupkey(tmp, &entry->addr), 6);
  btc_uint32_update(&ctx, hash32);
  btc_hash256_final(&ctx, hash2);

  hash = btc_read32le(hash2);
  index = hash % USED_COUNT;

  return &man->used[index];
}

static void
evict_fresh(btc_addrman_t *man, btc_netmap_t *bucket) {
  int64_t now = btc_timedata_now(man->timedata);
  btc_addrent_t *old = NULL;
  btc_addrent_t *entry;
  btc_mapiter_t it;

  btc_map_each(bucket, it) {
    entry = bucket->vals[it];

    if (btc_addrent_is_stale(entry, now)) {
      btc_netmap_del(bucket, &entry->addr);

      if (--entry->ref_count == 0) {
        btc_netmap_del(&man->map, &entry->addr);
        btc_randvec_pop(&man->rnd, entry);
        btc_addrent_destroy(entry);
        man->total_fresh -= 1;
      }

      continue;
    }

    if (old == NULL) {
      old = entry;
      continue;
    }

    if (entry->addr.time < old->addr.time)
      old = entry;
  }

  if (old == NULL)
    return;

  btc_netmap_del(bucket, &old->addr);

  if (--old->ref_count == 0) {
    btc_netmap_del(&man->map, &old->addr);
    btc_randvec_pop(&man->rnd, old);
    btc_addrent_destroy(old);
    man->total_fresh -= 1;
  }
}

static btc_addrent_t *
evict_used(btc_bucket_t *bucket) {
  btc_addrent_t *old = bucket->head;
  btc_addrent_t *entry;

  for (entry = bucket->head; entry != NULL; entry = entry->next) {
    if (entry->addr.time < old->addr.time)
      old = entry;
  }

  return old;
}

int
btc_addrman_add(btc_addrman_t *man,
                const btc_netaddr_t *addr,
                const btc_netaddr_t *src) {
  int64_t now = btc_timedata_now(man->timedata);
  btc_addrent_t *entry;
  btc_netmap_t *bucket;
  int32_t i;

  CHECK(addr->port != 0);

  entry = btc_netmap_get(&man->map, addr);

  if (entry != NULL) {
    int64_t penalty = 2 * 60 * 60;
    int64_t interval = 24 * 60 * 60;
    int32_t factor;

    /* No source means we're inserting
       this ourselves. No penalty. */
    if (src == NULL)
      penalty = 0;

    /* Update services. */
    entry->addr.services |= addr->services;

    /* Online? */
    if (now - addr->time < 24 * 60 * 60)
      interval = 60 * 60;

    /* Periodically update time. */
    if (entry->addr.time < addr->time - interval - penalty) {
      entry->addr.time = addr->time;
      man->needs_flush = 1;
    }

    /* Do not update if no new information is present. */
    if (entry->addr.time && addr->time <= entry->addr.time)
      return 0;

    /* Do not update if the entry was
       already in the "used" table. */
    if (entry->used)
      return 0;

    CHECK(entry->ref_count > 0);

    /* Do not update if the max
       reference count is reached. */
    if (entry->ref_count == MAX_REFS)
      return 0;

    CHECK(entry->ref_count < MAX_REFS);

    /* Stochastic test: previous refCount
       N: 2^N times harder to increase it. */
    factor = 1;

    for (i = 0; i < entry->ref_count; i++)
      factor *= 2;

    if (btc_uniform(factor) != 0)
      return 0;
  } else {
    if (src == NULL)
      src = &man->addr;

    entry = btc_addrent_create();

    btc_netaddr_copy(&entry->addr, addr);
    btc_netaddr_copy(&entry->src, src);

    man->total_fresh += 1;
  }

  bucket = fresh_bucket(man, entry);

  if (btc_netmap_has(bucket, &entry->addr))
    return 0;

  if (bucket->size >= FRESH_SIZE)
    evict_fresh(man, bucket);

  btc_netmap_put(bucket, &entry->addr, entry);
  entry->ref_count += 1;

  if (btc_netmap_put(&man->map, &entry->addr, entry))
    btc_randvec_push(&man->rnd, entry);

  man->needs_flush = 1;

  return 1;
}

int
btc_addrman_remove(btc_addrman_t *man, const btc_netaddr_t *addr) {
  btc_addrent_t *entry = btc_netmap_get(&man->map, addr);
  size_t i;

  if (entry == NULL)
    return 0;

  if (entry->used) {
    btc_addrent_t *head = entry;
    btc_bucket_t *bucket;

    CHECK(entry->ref_count == 0);

    while (head->prev != NULL)
      head = head->prev;

    for (i = 0; i < USED_COUNT; i++) {
      bucket = &man->used[i];

      if (bucket->head == head) {
        btc_list_remove(bucket, entry, btc_addrent_t);
        man->total_used -= 1;
        head = NULL;
        break;
      }
    }

    CHECK(head == NULL);
  } else {
    btc_netmap_t *bucket;

    for (i = 0; i < FRESH_COUNT; i++) {
      bucket = &man->fresh[i];

      if (btc_netmap_del(bucket, &entry->addr))
        entry->ref_count -= 1;
    }

    man->total_fresh -= 1;

    CHECK(entry->ref_count == 0);
  }

  CHECK(btc_netmap_del(&man->map, &entry->addr));

  btc_randvec_pop(&man->rnd, entry);

  btc_addrent_destroy(entry);

  return 1;
}

void
btc_addrman_mark_attempt(btc_addrman_t *man, const btc_netaddr_t *addr) {
  btc_addrent_t *entry = btc_netmap_get(&man->map, addr);

  if (entry == NULL)
    return;

  entry->attempts += 1;
  entry->last_attempt = btc_timedata_now(man->timedata);
}

void
btc_addrman_mark_success(btc_addrman_t *man, const btc_netaddr_t *addr) {
  btc_addrent_t *entry = btc_netmap_get(&man->map, addr);
  int64_t now;

  if (entry == NULL)
    return;

  now = btc_timedata_now(man->timedata);

  if (now - entry->addr.time > 20 * 60)
    entry->addr.time = now;
}

void
btc_addrman_mark_ack(btc_addrman_t *man,
                     const btc_netaddr_t *addr,
                     uint64_t services) {
  btc_addrent_t *entry = btc_netmap_get(&man->map, addr);
  btc_addrent_t *evicted;
  btc_netmap_t *old = NULL;
  btc_netmap_t *fresh;
  btc_bucket_t *bucket;
  int64_t now;
  size_t i;

  if (entry == NULL)
    return;

  now = btc_timedata_now(man->timedata);

  entry->addr.services |= services;

  entry->last_success = now;
  entry->last_attempt = now;
  entry->attempts = 0;

  if (entry->used)
    return;

  CHECK(entry->ref_count > 0);

  /* Remove from fresh. */
  for (i = 0; i < FRESH_COUNT; i++) {
    fresh = &man->fresh[i];

    if (btc_netmap_del(fresh, &entry->addr)) {
      entry->ref_count -= 1;
      old = fresh;
    }
  }

  CHECK(old != NULL);
  CHECK(entry->ref_count == 0);

  man->total_fresh -= 1;

  /* Find room in used bucket. */
  bucket = used_bucket(man, entry);

  if (bucket->length < USED_SIZE) {
    entry->used = 1;
    btc_list_push(bucket, entry, btc_addrent_t);
    man->total_used += 1;
    return;
  }

  /* No room. Evict. */
  evicted = evict_used(bucket);
  fresh = fresh_bucket(man, evicted);

  /* Move to entry's old bucket if no room. */
  if (fresh->size >= FRESH_SIZE)
    fresh = old;

  /* Swap to evicted's used bucket. */
  entry->used = 1;
  btc_list_replace(bucket, evicted, entry, btc_addrent_t);

  /* Move evicted to fresh bucket. */
  evicted->used = 0;
  btc_netmap_put(fresh, &evicted->addr, evicted);
  CHECK(evicted->ref_count == 0);
  evicted->ref_count += 1;
  man->total_fresh += 1;
}

int
btc_addrman_has_local(btc_addrman_t *man, const btc_netaddr_t *addr) {
  return btc_netmap_has(&man->local, addr);
}

const btc_netaddr_t *
btc_addrman_get_local(btc_addrman_t *man,
                      const btc_netaddr_t *dst,
                      uint64_t services) {
  btc_netaddr_t *best_addr = NULL;
  int best_reach = -1;
  int best_score = -1;
  btc_local_t *src;
  btc_mapiter_t it;
  int reach;

  if (dst == NULL) {
    btc_map_each(&man->local, it) {
      src = man->local.vals[it];

      if (src->score > best_score) {
        best_score = src->score;
        best_addr = &src->addr;
      }
    }
  } else {
    btc_map_each(&man->local, it) {
      src = man->local.vals[it];
      reach = btc_netaddr_reachability(&src->addr, dst);

      if (reach < best_reach)
        continue;

      if (reach > best_reach || src->score > best_score) {
        best_reach = reach;
        best_score = src->score;
        best_addr = &src->addr;
      }
    }
  }

  if (best_addr != NULL) {
    best_addr->time = btc_timedata_now(man->timedata);
    best_addr->services = services;
  }

  return best_addr;
}

int
btc_addrman_add_local(btc_addrman_t *man,
                      const btc_netaddr_t *addr,
                      int score) {
  btc_local_t *local;

  if (!btc_netaddr_is_routable(addr))
    return 0;

  local = btc_netmap_get(&man->local, addr);

  if (local != NULL) {
    if (score > local->score)
      local->score = score;

    return 0;
  }

  local = btc_local_create();
  local->addr = *addr;
  local->type = score;
  local->score = score;

  local->addr.services = BTC_NET_DEFAULT_SERVICES;
  local->addr.time = btc_now();

  btc_netmap_put(&man->local, &local->addr, local);

  return 1;
}

int
btc_addrman_mark_local(btc_addrman_t *man, const btc_netaddr_t *addr) {
  btc_local_t *local = btc_netmap_get(&man->local, addr);

  if (local == NULL)
    return 0;

  local->score += 1;

  return 1;
}

const btc_netmap_t *
btc_addrman_map(const btc_addrman_t *man) {
  return &man->map;
}

btc_vector_t *
btc_addrman_getaddr(btc_addrman_t *man) {
  int64_t now = btc_timedata_now(man->timedata);
  btc_vector_t *addrs = btc_vector_create();
  btc_addrent_t *entry;
  size_t i, j, max;

  max = (23 * man->rnd.length) / 100;

  if (max > 2500)
    max = 2500;

  btc_vector_grow(addrs, max);

  for (i = 0; i < man->rnd.length && addrs->length < max; i++) {
    j = i + btc_uniform(man->rnd.length - i);
    entry = btc_randvec_swap(&man->rnd, i, j);

    if (!btc_addrent_is_stale(entry, now))
      btc_vector_push(addrs, &entry->addr);
  }

  return addrs;
}

size_t
btc_addrman_size(const btc_addrman_t *man) {
  size_t size = 0;
  int i;

  size += 4;
  size += 4;
  size += 32;

  size += btc_size_size(man->rnd.length);
  size += man->rnd.length * BTC_ADDRENT_SIZE;

  for (i = 0; i < FRESH_COUNT; i++) {
    const btc_netmap_t *bucket = &man->fresh[i];

    size += btc_size_size(bucket->size);
    size += bucket->size * 4;
  }

  for (i = 0; i < USED_COUNT; i++) {
    const btc_bucket_t *bucket = &man->used[i];

    size += btc_size_size(bucket->length);
    size += bucket->length * 4;
  }

  return size;
}

static uint8_t *
btc_addrman_write(uint8_t *zp, const btc_addrman_t *man) {
  size_t i;

  zp = btc_uint32_write(zp, SER_VERSION);
  zp = btc_uint32_write(zp, man->network->magic);
  zp = btc_raw_write(zp, man->key, 32);

  zp = btc_size_write(zp, man->rnd.length);

  for (i = 0; i < man->rnd.length; i++)
    zp = btc_addrent_write(zp, man->rnd.items[i]);

  for (i = 0; i < FRESH_COUNT; i++) {
    const btc_netmap_t *bucket = &man->fresh[i];
    btc_mapiter_t it;

    zp = btc_size_write(zp, bucket->size);

    btc_map_each(bucket, it) {
      const btc_addrent_t *entry = bucket->vals[it];

      zp = btc_uint32_write(zp, entry->rand_pos);
    }
  }

  for (i = 0; i < USED_COUNT; i++) {
    const btc_bucket_t *bucket = &man->used[i];
    const btc_addrent_t *entry;

    zp = btc_size_write(zp, bucket->length);

    for (entry = bucket->head; entry != NULL; entry = entry->next)
      zp = btc_uint32_write(zp, entry->rand_pos);
  }

  return zp;
}

static int
btc_addrman_read(btc_addrman_t *man, const uint8_t **xp, size_t *xn) {
  uint32_t version, magic;
  size_t i, j, length;

  btc_addrman_reset(man);

  if (!btc_uint32_read(&version, xp, xn))
    goto fail;

  if (!btc_uint32_read(&magic, xp, xn))
    goto fail;

  if (version != SER_VERSION)
    goto fail;

  if (magic != man->network->magic)
    goto fail;

  if (!btc_raw_read(man->key, 32, xp, xn))
    goto fail;

  if (!btc_size_read(&length, xp, xn))
    goto fail;

  for (i = 0; i < length; i++) {
    btc_addrent_t *entry = btc_addrent_create();

    if (!btc_addrent_read(entry, xp, xn)) {
      btc_addrent_destroy(entry);
      goto fail;
    }

    if (!btc_netmap_put(&man->map, &entry->addr, entry)) {
      btc_addrent_destroy(entry);
      goto fail;
    }

    btc_randvec_push(&man->rnd, entry);
  }

  for (i = 0; i < FRESH_COUNT; i++) {
    btc_netmap_t *bucket = &man->fresh[i];

    if (!btc_size_read(&length, xp, xn))
      goto fail;

    for (j = 0; j < length; j++) {
      btc_addrent_t *entry;
      uint32_t pos;

      if (!btc_uint32_read(&pos, xp, xn))
        goto fail;

      if (pos >= man->rnd.length)
        goto fail;

      entry = man->rnd.items[pos];

      if (entry->ref_count == 0)
        man->total_fresh++;

      entry->ref_count++;

      btc_netmap_put(bucket, &entry->addr, entry);
    }

    if (bucket->size > FRESH_SIZE)
      goto fail; /* Bucket size mismatch. */
  }

  for (i = 0; i < USED_COUNT; i++) {
    btc_bucket_t *bucket = &man->used[i];

    if (!btc_size_read(&length, xp, xn))
      goto fail;

    for (j = 0; j < length; j++) {
      btc_addrent_t *entry;
      uint32_t pos;

      if (!btc_uint32_read(&pos, xp, xn))
        goto fail;

      if (pos >= man->rnd.length)
        goto fail;

      entry = man->rnd.items[pos];

      if (entry->ref_count != 0 || entry->used)
        goto fail;

      man->total_used++;

      entry->used = 1;

      btc_list_push(bucket, entry, btc_addrent_t);
    }

    if (bucket->length > USED_SIZE)
      goto fail; /* Bucket size mismatch. */
  }

  if (*xn != 0)
    goto fail;

  for (i = 0; i < man->rnd.length; i++) {
    btc_addrent_t *entry = man->rnd.items[i];

    if (!entry->used && entry->ref_count == 0)
      goto fail;
  }

  return 1;
fail:
  btc_addrman_reset(man);
  return 0;
}

size_t
btc_addrman_export(uint8_t *zp, const btc_addrman_t *man) {
  return btc_addrman_write(zp, man) - zp;
}

int
btc_addrman_import(btc_addrman_t *man, const uint8_t *xp, size_t xn) {
  return btc_addrman_read(man, &xp, &xn);
}
