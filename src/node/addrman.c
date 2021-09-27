/*!
 * addrman.c - address manager for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <math.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <io/core.h>

#include <node/addrman.h>
#include <node/logger.h>
#include <node/timedata.h>

#include <satoshi/crypto/hash.h>
#include <satoshi/crypto/rand.h>
#include <satoshi/list.h>
#include <satoshi/map.h>
#include <satoshi/net.h>
#include <satoshi/netaddr.h>
#include <satoshi/network.h>
#include <satoshi/util.h>
#include <satoshi/vector.h>

#include "../bio.h"
#include "../impl.h"
#include "../internal.h"

/*
 * Constants
 */

#define HORIZON_DAYS 30
#define MAX_RETRIES 3
#define MIN_FAIL_DAYS 7
#define MAX_FAILURES 10
#define MAX_REFS 8
#define MAX_FRESH_BUCKETS 1024
#define MAX_USED_BUCKETS 256
#define MAX_ENTRIES 64

/*
 * Address Entry
 */

DEFINE_OBJECT(btc_addrent, SCOPE_STATIC)

static void
btc_addrent_init(btc_addrent_t *entry) {
  btc_netaddr_init(&entry->addr);
  btc_netaddr_init(&entry->src);
  entry->prev = NULL;
  entry->next = NULL;
  entry->used = 0;
  entry->ref_count = 0;
  entry->attempts = 0;
  entry->last_success = 0;
  entry->last_attempt = 0;
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
  z->prev = x->prev;
  z->next = x->next;
  z->used = x->used;
  z->ref_count = x->ref_count;
  z->attempts = x->attempts;
  z->last_success = x->last_success;
  z->last_attempt = x->last_attempt;
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

/*
 * Used Bucket
 */

typedef struct btc_bucket_s {
  btc_addrent_t *head;
  btc_addrent_t *tail;
  size_t length;
} btc_bucket_t;

static btc_bucket_t *
btc_bucket_create(void) {
  btc_bucket_t *z;
  btc_list_create(z, btc_bucket_t);
  return z;
}

static void
btc_bucket_destroy(btc_bucket_t *z) {
  btc_list_destroy(z);
}

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
 * Address Manager
 */

struct btc_addrman_s {
  const btc_network_t *network;
  btc_logger_t *logger;
  const btc_timedata_t *timedata;
  btc_netaddr_t addr;
  uint64_t services;
  uint8_t key[32];
  btc_addrmap_t *map;
  btc_vector_t fresh;
  size_t total_fresh;
  btc_vector_t used;
  size_t total_used;
  btc_addrmap_t *local;
  btc_addrmap_t *banned;
  int needs_flush;
  int flushing;
};

struct btc_addrman_s *
btc_addrman_create(const btc_network_t *network) {
  struct btc_addrman_s *man =
    (struct btc_addrman_s *)btc_malloc(sizeof(struct btc_addrman_s));
  int i;

  memset(man, 0, sizeof(*man));

  man->network = network;
  man->logger = NULL;
  man->timedata = NULL;
  btc_netaddr_init(&man->addr);
  btc_netaddr_localize(&man->addr);
  man->addr.services = BTC_NET_LOCAL_SERVICES;
  man->addr.time = btc_now();
  man->services = BTC_NET_LOCAL_SERVICES;
  btc_getrandom(man->key, 32);
  man->map = btc_addrmap_create();
  btc_vector_init(&man->fresh);
  man->total_fresh = 0;
  btc_vector_init(&man->used);
  man->total_used = 0;
  man->local = btc_addrmap_create();
  man->banned = btc_addrmap_create();
  man->needs_flush = 0;
  man->flushing = 0;

  for (i = 0; i < MAX_FRESH_BUCKETS; i++)
    btc_vector_push(&man->fresh, btc_addrmap_create());

  for (i = 0; i < MAX_USED_BUCKETS; i++)
    btc_vector_push(&man->used, btc_bucket_create());

  return man;
}

void
btc_addrman_destroy(struct btc_addrman_s *man) {
  btc_addrmapiter_t iter;
  size_t i;

  btc_addrmap_iterate(&iter, man->map);

  while (btc_addrmap_next(&iter))
    btc_addrent_destroy(iter.val);

  for (i = 0; i < MAX_FRESH_BUCKETS; i++)
    btc_addrmap_destroy(man->fresh.items[i]);

  for (i = 0; i < MAX_USED_BUCKETS; i++)
    btc_bucket_destroy(man->used.items[i]);

  btc_addrmap_iterate(&iter, man->local);

  while (btc_addrmap_next(&iter))
    btc_local_destroy(iter.val);

  btc_addrmap_iterate(&iter, man->banned);

  while (btc_addrmap_next(&iter))
    btc_netaddr_destroy(iter.val);

  btc_addrmap_destroy(man->map);
  btc_vector_clear(&man->fresh);
  btc_vector_clear(&man->used);
  btc_addrmap_destroy(man->local);
  btc_addrmap_destroy(man->banned);
  btc_free(man);
}

void
btc_addrman_set_logger(struct btc_addrman_s *man, btc_logger_t *logger) {
  man->logger = logger;
}

void
btc_addrman_set_timedata(struct btc_addrman_s *man, const btc_timedata_t *td) {
  man->timedata = td;
}

static void
btc_addrman_log(struct btc_addrman_s *man, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  btc_logger_write(man->logger, "addrman", fmt, ap);
  va_end(ap);
}

int
btc_addrman_open(struct btc_addrman_s *man) {
  const btc_network_t *network = man->network;
  int64_t now = btc_now();
  btc_sockaddr_t *res, *p;
  btc_netaddr_t addr;
  size_t i;

  for (i = 0; i < network->seeds.length; i++) {
    const char *seed = network->seeds.items[i];

    btc_addrman_log(man, "Resolving %s...", seed);

    if (btc_getaddrinfo(&res, seed)) {
      int total = 0;

      for (p = res; p != NULL; p = p->next) {
        btc_netaddr_set_sockaddr(&addr, p);

        addr.time = now;
        addr.services = BTC_NET_LOCAL_SERVICES;
        addr.port = network->port;

        btc_addrman_add(man, &addr, NULL);

        total += 1;
      }

      btc_addrman_log(man, "Resolved %d seeds from %s.", total, seed);

      btc_freeaddrinfo(res);
    } else {
      btc_addrman_log(man, "Could not resolve %s.", seed);
    }

    /* Temporary. */
    if (btc_addrmap_size(man->map) >= 10)
      break;
  }

  btc_addrman_log(man, "Resolved %zu seeds.", btc_addrman_size(man));

  return btc_addrman_size(man) > 0;
}

void
btc_addrman_close(struct btc_addrman_s *man) {
  (void)man;
}

void
btc_addrman_flush(struct btc_addrman_s *man) {
  (void)man;
}

size_t
btc_addrman_size(struct btc_addrman_s *man) {
  return man->total_fresh + man->total_used;
}

int
btc_addrman_is_full(struct btc_addrman_s *man) {
  return man->total_fresh >= MAX_FRESH_BUCKETS * MAX_ENTRIES;
}

void
btc_addrman_reset(struct btc_addrman_s *man) {
  (void)man;
}

void
btc_addrman_ban(struct btc_addrman_s *man, const btc_netaddr_t *addr) {
  btc_netaddr_t *entry = btc_netaddr_clone(addr);

  entry->port = 0;
  entry->time = btc_now();

  if (!btc_addrmap_put(man->banned, entry, entry))
    btc_netaddr_destroy(entry);
}

void
btc_addrman_unban(struct btc_addrman_s *man, const btc_netaddr_t *addr) {
  btc_netaddr_t key = *addr;

  key.port = 0;

  btc_addrmap_del(man->banned, &key);
}

int
btc_addrman_is_banned(struct btc_addrman_s *man, const btc_netaddr_t *addr) {
  btc_netaddr_t key = *addr;
  btc_netaddr_t *entry;

  key.port = 0;

  entry = btc_addrmap_get(man->banned, &key);

  if (entry == NULL)
    return 0;

  if (btc_now() > entry->time + 24 * 60 * 60) {
    btc_addrmap_del(man->banned, &key);
    btc_netaddr_destroy(entry);
    return 0;
  }

  return 1;
}

void
btc_addrman_clear_banned(struct btc_addrman_s *man) {
  btc_addrmapiter_t iter;

  btc_addrmap_iterate(&iter, man->banned);

  while (btc_addrmap_next(&iter))
    btc_netaddr_destroy(iter.val);

  btc_addrmap_reset(man->banned);
}

const btc_addrent_t *
btc_addrman_get(struct btc_addrman_s *man) {
  btc_vector_t *buckets = NULL;
  btc_addrent_t *entry;
  double factor, num;
  size_t i, index;
  int64_t now;

  if (man->total_fresh > 0)
    buckets = &man->fresh;

  if (man->total_used > 0) {
    if (man->total_fresh == 0 || btc_uniform(2) == 0)
      buckets = &man->used;
  }

  if (buckets == NULL)
    return NULL;

  now = btc_timedata_now(man->timedata);
  factor = 1.0;

  for (;;) {
    i = btc_uniform(buckets->length);

    if (buckets == &man->used) {
      btc_bucket_t *bucket = buckets->items[i];

      if (bucket->length == 0)
        continue;

      index = btc_uniform(bucket->length);
      entry = bucket->head;

      while (index--)
        entry = entry->next;
    } else {
      btc_addrmap_t *bucket = buckets->items[i];
      btc_addrmapiter_t iter;

      if (btc_addrmap_size(bucket) == 0)
        continue;

      index = btc_uniform(btc_addrmap_size(bucket));

      btc_addrmap_iterate(&iter, bucket);

      while (btc_addrmap_next(&iter)) {
        entry = iter.val;

        if (index == 0)
          break;

        index -= 1;
      }
    }

    num = btc_uniform(1U << 30);

    if (num < factor * btc_addrent_chance(entry, now) * (double)(1U << 30))
      return entry;

    factor *= 1.2;
  }
}

static btc_addrmap_t *
fresh_bucket(struct btc_addrman_s *man, const btc_addrent_t *entry) {
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

  hash32 = read32le(hash1) % 64;

  btc_hash256_init(&ctx);
  btc_hash256_update(&ctx, man->key, 32);
  btc_hash256_update(&ctx, btc_netaddr_groupkey(tmp, &entry->src), 6);
  btc_hash256_update(&ctx, &hash32, sizeof(hash32));
  btc_hash256_final(&ctx, hash2);

  hash = read32le(hash2);
  index = hash % man->fresh.length;

  return man->fresh.items[index];
}

static btc_bucket_t *
used_bucket(struct btc_addrman_s *man, const btc_addrent_t *entry) {
  uint32_t hash32, hash, index;
  uint8_t hash1[32];
  uint8_t hash2[32];
  btc_hash256_t ctx;
  uint8_t tmp[6];

  btc_hash256_init(&ctx);
  btc_hash256_update(&ctx, man->key, 32);
  btc_hash256_update(&ctx, entry->addr.raw, 16);
  btc_hash256_update(&ctx, &entry->addr.port, sizeof(entry->addr.port));
  btc_hash256_final(&ctx, hash1);

  hash32 = read32le(hash1) % 8;

  btc_hash256_init(&ctx);
  btc_hash256_update(&ctx, man->key, 32);
  btc_hash256_update(&ctx, btc_netaddr_groupkey(tmp, &entry->addr), 6);
  btc_hash256_update(&ctx, &hash32, sizeof(hash32));
  btc_hash256_final(&ctx, hash2);

  hash = read32le(hash2);
  index = hash % man->used.length;

  return man->used.items[index];
}

static int
is_stale(struct btc_addrman_s *man, const btc_addrent_t *entry) {
  int64_t now = btc_timedata_now(man->timedata);

  if (entry->last_attempt != 0 && entry->last_attempt >= now - 60)
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

static void
evict_fresh(struct btc_addrman_s *man, btc_addrmap_t *bucket) {
  btc_addrent_t *old = NULL;
  btc_addrmapiter_t iter;
  btc_addrent_t *entry;

  btc_addrmap_iterate(&iter, bucket);

  while (btc_addrmap_next(&iter)) {
    entry = iter.val;

    if (is_stale(man, entry)) {
      btc_addrmap_del(bucket, &entry->addr);

      if (--entry->ref_count == 0) {
        btc_addrmap_del(man->map, &entry->addr);
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

  btc_addrmap_del(bucket, &old->addr);

  if (--old->ref_count == 0) {
    btc_addrmap_del(man->map, &old->addr);
    btc_addrent_destroy(old);
    man->total_fresh -= 1;
  }
}

static btc_addrent_t *
evict_used(struct btc_addrman_s *man, btc_bucket_t *bucket) {
  btc_addrent_t *old = bucket->head;
  btc_addrent_t *entry;

  (void)man;

  for (entry = bucket->head; entry != NULL; entry = entry->next) {
    if (entry->addr.time < old->addr.time)
      old = entry;
  }

  return old;
}

int
btc_addrman_add(struct btc_addrman_s *man,
                const btc_netaddr_t *addr,
                const btc_netaddr_t *src) {
  int64_t now = btc_timedata_now(man->timedata);
  btc_addrent_t *entry;
  btc_addrmap_t *bucket;
  int32_t i;

  CHECK(addr->port != 0);

  entry = btc_addrmap_get(man->map, addr);

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

    if (entry->addr.time <= 100000000 || entry->addr.time > now + 10 * 60)
      entry->addr.time = now - 5 * 24 * 60 * 60;

    man->total_fresh += 1;
  }

  bucket = fresh_bucket(man, entry);

  if (btc_addrmap_has(bucket, &entry->addr))
    return 0;

  if (btc_addrmap_size(bucket) >= MAX_ENTRIES)
    evict_fresh(man, bucket);

  btc_addrmap_put(bucket, &entry->addr, entry);
  entry->ref_count += 1;

  btc_addrmap_put(man->map, &entry->addr, entry);
  man->needs_flush = 1;

  return 1;
}

int
btc_addrman_remove(struct btc_addrman_s *man, const btc_netaddr_t *addr) {
  btc_addrent_t *entry = btc_addrmap_get(man->map, addr);
  size_t i;

  if (entry == NULL)
    return 0;

  if (entry->used) {
    btc_addrent_t *head = entry;
    btc_bucket_t *bucket;

    CHECK(entry->ref_count == 0);

    while (head->prev != NULL)
      head = head->prev;

    for (i = 0; i < man->used.length; i++) {
      bucket = man->used.items[i];

      if (bucket->head == head) {
        btc_list_remove(bucket, entry, btc_addrent_t);
        man->total_used -= 1;
        head = NULL;
        break;
      }
    }

    CHECK(head == NULL);
  } else {
    btc_addrmap_t *bucket;

    for (i = 0; i < man->fresh.length; i++) {
      bucket = man->fresh.items[i];

      if (btc_addrmap_del(bucket, &entry->addr))
        entry->ref_count -= 1;
    }

    man->total_fresh -= 1;

    CHECK(entry->ref_count == 0);
  }

  CHECK(btc_addrmap_del(man->map, &entry->addr));

  btc_addrent_destroy(entry);

  return 1;
}

void
btc_addrman_mark_attempt(struct btc_addrman_s *man,
                         const btc_netaddr_t *addr) {
  btc_addrent_t *entry = btc_addrmap_get(man->map, addr);

  if (entry == NULL)
    return;

  entry->attempts += 1;
  entry->last_attempt = btc_timedata_now(man->timedata);
}

void
btc_addrman_mark_success(struct btc_addrman_s *man,
                         const btc_netaddr_t *addr) {
  btc_addrent_t *entry = btc_addrmap_get(man->map, addr);
  int64_t now;

  if (entry == NULL)
    return;

  now = btc_timedata_now(man->timedata);

  if (now - entry->addr.time > 20 * 60)
    entry->addr.time = now;
}

void
btc_addrman_mark_ack(struct btc_addrman_s *man,
                     const btc_netaddr_t *addr,
                     uint64_t services) {
  btc_addrent_t *entry = btc_addrmap_get(man->map, addr);
  btc_addrent_t *evicted;
  btc_addrmap_t *old = NULL;
  btc_addrmap_t *fresh;
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
  for (i = 0; i < man->fresh.length; i++) {
    fresh = man->fresh.items[i];

    if (btc_addrmap_del(fresh, &entry->addr)) {
      entry->ref_count -= 1;
      old = fresh;
    }
  }

  CHECK(old != NULL);
  CHECK(entry->ref_count == 0);

  man->total_fresh -= 1;

  /* Find room in used bucket. */
  bucket = used_bucket(man, entry);

  if (bucket->length < MAX_ENTRIES) {
    entry->used = 1;
    btc_list_push(bucket, entry, btc_addrent_t);
    man->total_used += 1;
    return;
  }

  /* No room. Evict. */
  evicted = evict_used(man, bucket);
  fresh = fresh_bucket(man, evicted);

  /* Move to entry's old bucket if no room. */
  if (btc_addrmap_size(fresh) >= MAX_ENTRIES)
    fresh = old;

  /* Swap to evicted's used bucket. */
  entry->used = 1;
  btc_list_replace(bucket, evicted, entry, btc_addrent_t);

  /* Move evicted to fresh bucket. */
  evicted->used = 0;
  btc_addrmap_put(fresh, &evicted->addr, evicted);
  CHECK(evicted->ref_count == 0);
  evicted->ref_count += 1;
  man->total_fresh += 1;
}

int
btc_addrman_has_local(struct btc_addrman_s *man,
                      const btc_netaddr_t *src) {
  return btc_addrmap_has(man->local, src);
}

const btc_netaddr_t *
btc_addrman_get_local(struct btc_addrman_s *man,
                      const btc_netaddr_t *src) {
  btc_netaddr_t *best_dst = NULL;
  btc_addrmapiter_t iter;
  int best_reach = -1;
  int best_score = -1;
  btc_local_t *dst;
  int reach;

  btc_addrmap_iterate(&iter, man->local);

  if (src == NULL) {
    while (btc_addrmap_next(&iter)) {
      dst = iter.val;

      if (dst->score > best_score) {
        best_score = dst->score;
        best_dst = &dst->addr;
      }
    }

    return best_dst;
  }

  while (btc_addrmap_next(&iter)) {
    dst = iter.val;
    reach = btc_netaddr_reachability(src, &dst->addr);

    if (reach < best_reach)
      continue;

    if (reach > best_reach || dst->score > best_score) {
      best_reach = reach;
      best_score = dst->score;
      best_dst = &dst->addr;
    }
  }

  if (best_dst)
    best_dst->time = btc_timedata_now(man->timedata);

  return best_dst;
}

int
btc_addrman_add_local(struct btc_addrman_s *man,
                      const btc_netaddr_t *addr,
                      int score) {
  btc_local_t *local;

  if (!btc_netaddr_is_routable(addr))
    return 0;

  if (btc_addrmap_has(man->local, addr))
    return 0;

  local = btc_local_create();
  local->addr = *addr;
  local->type = score;
  local->score = score;

  local->addr.services = man->services;

  btc_addrmap_put(man->local, &local->addr, local);

  return 1;
}

int
btc_addrman_mark_local(struct btc_addrman_s *man,
                       const btc_netaddr_t *addr) {
  btc_local_t *local = btc_addrmap_get(man->local, addr);

  if (local == NULL)
    return 0;

  local->score += 1;

  return 1;
}

void
btc_addrman_iterate(btc_addriter_t *iter, struct btc_addrman_s *man) {
  btc_addrmap_iterate(iter, man->map);
}

int
btc_addrman_next(const btc_netaddr_t **addr, btc_addriter_t *iter) {
  if (btc_addrmap_next(iter)) {
    *addr = iter->val;
    return 1;
  }
  return 0;
}
