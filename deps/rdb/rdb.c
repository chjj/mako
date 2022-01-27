/*!
 * rdb.c - database for mako
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include "win.h"
#else
#  include <sys/types.h>
#  include <sys/time.h>
#  include <sys/stat.h>
#  ifdef RDB_MMAP
#    include <sys/mman.h>
#  endif
#  include <fcntl.h>
#  include <unistd.h>
#  ifdef __GLIBC__
#    include <malloc.h>
#  endif
#  ifdef RDB_PTHREAD
#    include <pthread.h>
#  endif
#endif

#include "rdb.h"

#ifndef RDB_PTHREAD
#  undef RDB_BACKGROUND_COMPACTION
#endif

/*
 * Constants
 */

#define RDB_KEY_SIZE 37
#define RDB_VALUE_SIZE 0x7fff
#define RDB_NODE_SIZE (1 + 1 + RDB_KEY_SIZE + 2 + 16 * 8)
#define RDB_TREE_DEPTH (RDB_KEY_SIZE * 2)

#define RDB_FLAG_WRITTEN (1 << 0)
#define RDB_FLAG_SAVED (1 << 1)
#define RDB_FLAG_VALUE (1 << 2)
#define RDB_FLAG_RESOLVED (1 << 3)

#define RDB_NODE_NULL 0
#define RDB_NODE_INTERNAL 1
#define RDB_NODE_LEAF 2
#define RDB_NODE_PTR 3

#define RDB_PATH_MAX 1024

#define RDB_META_SIZE (4 + (8 * 3) + 20)
#define RDB_MAGIC 0x6d616b6f
#define RDB_WRITE_BUFFER (64 << 20)
#define RDB_READ_BUFFER (1 << 20)
#define RDB_SLAB_SIZE (RDB_READ_BUFFER - (RDB_READ_BUFFER % RDB_META_SIZE))

#define RDB_COMPACT_THRESH (UINT64_C(3) << 30)
#define RDB_COMPACT_MAXMEM (sizeof(void *) >= 8 ? (1024 << 20) : (512 << 20))

/*
 * Macros
 */

#define CHECK(x) do { if (!(x)) abort(); } while (0)

/*
 * SHA256
 */

static void
rdb_sha256(uint8_t *zp, const uint8_t *xp, size_t xn,
                        const uint8_t *yp, size_t yn) {
  static const uint32_t K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };

  uint32_t a, b, c, d, e, f, g, h, t1, t2;
  size_t n = xn + yn;
  uint8_t block[64];
  uint32_t state[8];
  uint32_t W[64];
  uint8_t *chunk;
  int i = 0;

  CHECK(n <= 55);

  /* Concat x & y. */
  while (xn--)
    block[i++] = *xp++;

  while (yn--)
    block[i++] = *yp++;

  /* Pad. */
  block[i++] = 0x80;

  while (i < 62)
    block[i++] = 0x00;

  block[62] = (n << 3) >> 8;
  block[63] = (n << 3) & 0xff;

  chunk = block;

  state[0] = 0x6a09e667;
  state[1] = 0xbb67ae85;
  state[2] = 0x3c6ef372;
  state[3] = 0xa54ff53a;
  state[4] = 0x510e527f;
  state[5] = 0x9b05688c;
  state[6] = 0x1f83d9ab;
  state[7] = 0x5be0cd19;

  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  f = state[5];
  g = state[6];
  h = state[7];

#define ROTR32(w, b) (((w) >> (b)) | ((w) << (32 - (b))))
#define Ch(x, y, z) ((x & (y ^ z)) ^ z)
#define Maj(x, y, z) ((x & (y | z)) | (y & z))
#define Sigma0(x) (ROTR32(x,  2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define Sigma1(x) (ROTR32(x,  6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define sigma0(x) (ROTR32(x,  7) ^ ROTR32(x, 18) ^ (x >>  3))
#define sigma1(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ (x >> 10))

  for (i = 0; i < 16; i++) {
    W[i] = ((uint32_t)chunk[0] << 24)
         | ((uint32_t)chunk[1] << 16)
         | ((uint32_t)chunk[2] <<  8)
         | ((uint32_t)chunk[3] <<  0);
    chunk += 4;
  }

  for (i = 16; i < 64; i++)
    W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];

  for (i = 0; i < 64; i++) {
    t1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
    t2 = Sigma0(a) + Maj(a, b, c);

    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

#undef ROTR32
#undef Ch
#undef Maj
#undef Sigma0
#undef Sigma1
#undef sigma0
#undef sigma1

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;

  /* 20 bytes only. */
  for (i = 0; i < 5; i++) {
    zp[0] = state[i] >> 24;
    zp[1] = state[i] >> 16;
    zp[2] = state[i] >>  8;
    zp[3] = state[i] >>  0;
    zp += 4;
  }
}

/*
 * I/O Helpers
 */

static int
safe_open(const char *name, int flags, unsigned int mode) {
  int fd;

#ifdef O_CLOEXEC
  if (flags & O_CREAT)
    fd = open(name, flags | O_CLOEXEC, mode);
  else
    fd = open(name, flags | O_CLOEXEC);

  if (fd != -1 || errno != EINVAL)
    return fd;
#endif

  if (flags & O_CREAT)
    fd = open(name, flags, mode);
  else
    fd = open(name, flags);

#ifdef FD_CLOEXEC
  if (fd != -1) {
    int r = fcntl(fd, F_GETFD);

    if (r != -1)
      fcntl(fd, F_SETFD, r | FD_CLOEXEC);
  }
#endif

  return fd;
}

static int
safe_write(int fd, const void *src, size_t len) {
  const unsigned char *buf = (const unsigned char *)src;
  size_t max = INT_MAX;
  int nwrite;

  while (len > 0) {
    if (max > len)
      max = len;

    do {
      nwrite = write(fd, buf, max);
    } while (nwrite < 0 && errno == EINTR);

    if (nwrite <= 0)
      break;

    if ((size_t)nwrite > max)
      abort();

    buf += nwrite;
    len -= nwrite;
  }

  return len == 0;
}

static int
safe_pread(int fd, void *dst, size_t len, int64_t pos) {
  unsigned char *buf = (unsigned char *)dst;
  size_t max = INT_MAX;
  int nread;

  while (len > 0) {
    if (max > len)
      max = len;

    do {
      nread = pread(fd, buf, max, pos);
    } while (nread < 0 && errno == EINTR);

    if (nread <= 0)
      break;

    if ((size_t)nread > max)
      abort();

    buf += nread;
    len -= nread;
    pos += nread;
  }

  return len == 0;
}

static int
open_lock(const char *name, unsigned int mode) {
  int flags = O_RDWR | O_CREAT | O_TRUNC;
  int fd = safe_open(name, flags, mode);
  struct flock fl;

  if (fd == -1)
    return -1;

  memset(&fl, 0, sizeof(fl));

  fl.l_type = F_WRLCK;

  if (fcntl(fd, F_SETLK, &fl) == -1) {
    close(fd);
    return -1;
  }

  return fd;
}

static int
close_lock(int fd) {
  struct flock fl;

  memset(&fl, 0, sizeof(fl));

  fl.l_type = F_UNLCK;

  if (fcntl(fd, F_SETLK, &fl) == -1) {
    close(fd);
    return -1;
  }

  return close(fd);
}

static int
random_key(uint8_t *key) {
  struct timeval tv;

  memset(&tv, 0, sizeof(tv));

  if (gettimeofday(&tv, NULL) != 0)
    return 0;

  rdb_sha256(key, (uint8_t *)&tv, sizeof(tv), 0, 0);

  return 1;
}

/*
 * Allocator
 */

#if defined(RDB_TLS)
static RDB_TLS size_t rdb_usage = 0;
#  define RDB_USAGE_LOCK ((void)0)
#  define RDB_USAGE_UNLOCK ((void)0)
#elif defined(RDB_PTHREAD)
static size_t rdb_usage = 0;
static pthread_mutex_t rdb_usage_lock = PTHREAD_MUTEX_INITIALIZER;
#  define RDB_USAGE_LOCK CHECK(pthread_mutex_lock(&rdb_usage_lock) == 0)
#  define RDB_USAGE_UNLOCK CHECK(pthread_mutex_unlock(&rdb_usage_lock) == 0)
#else
static size_t rdb_usage = 0;
#  define RDB_USAGE_LOCK ((void)0)
#  define RDB_USAGE_UNLOCK ((void)0)
#endif

static size_t
rdb_malloc_usage(size_t alloc) {
  if (alloc == 0)
    return 0;

  if (sizeof(void *) == 8)
    return ((alloc + 31) >> 4) << 4;

  if (sizeof(void *) == 4)
    return ((alloc + 15) >> 3) << 3;

  abort();

  return 0;
}

static void *
rdb_malloc(size_t size) {
  void *ptr = malloc(size);

  if (ptr == NULL)
    abort();

  RDB_USAGE_LOCK;

  rdb_usage += rdb_malloc_usage(size);

  RDB_USAGE_UNLOCK;

  return ptr;
}

static void *
rdb_realloc(void *ptr, size_t old_size, size_t new_size) {
  size_t old_usage = rdb_malloc_usage(old_size);

  RDB_USAGE_LOCK;

  if (old_usage > rdb_usage)
    old_usage = rdb_usage;

  rdb_usage -= old_usage;
  rdb_usage += rdb_malloc_usage(new_size);

  RDB_USAGE_UNLOCK;

  ptr = realloc(ptr, new_size);

  if (ptr == NULL)
    abort();

  return ptr;
}

static void
rdb_free(void *ptr, size_t size) {
  size_t usage = rdb_malloc_usage(size);

  RDB_USAGE_LOCK;

  if (usage > rdb_usage)
    usage = rdb_usage;

  rdb_usage -= usage;

  RDB_USAGE_UNLOCK;

  free(ptr);
}

/*
 * Serialization
 */

static uint8_t *
rdb_uint8_write(uint8_t *zp, uint8_t x) {
  *zp++ = x;
  return zp;
}

static int
rdb_uint8_read(uint8_t *zp, const uint8_t **xp, size_t *xn) {
  if (*xn < 1)
    return 0;

  *zp = (*xp)[0];
  *xp += 1;
  *xn -= 1;

  return 1;
}

static uint8_t *
rdb_uint16_write(uint8_t *zp, uint16_t x) {
  *zp++ = (x >> 0);
  *zp++ = (x >> 8);
  return zp;
}

static int
rdb_uint16_read(uint16_t *zp, const uint8_t **xp, size_t *xn) {
  if (*xn < 2)
    return 0;

  *zp = ((uint16_t)(*xp)[0] << 0)
      | ((uint16_t)(*xp)[1] << 8);

  *xp += 2;
  *xn -= 2;

  return 1;
}

static uint8_t *
rdb_uint32_write(uint8_t *zp, uint32_t x) {
  *zp++ = (x >>  0);
  *zp++ = (x >>  8);
  *zp++ = (x >> 16);
  *zp++ = (x >> 24);
  return zp;
}

static int
rdb_uint32_read(uint32_t *zp, const uint8_t **xp, size_t *xn) {
  if (*xn < 4)
    return 0;

  *zp = ((uint32_t)(*xp)[0] <<  0)
      | ((uint32_t)(*xp)[1] <<  8)
      | ((uint32_t)(*xp)[2] << 16)
      | ((uint32_t)(*xp)[3] << 24);

  *xp += 4;
  *xn -= 4;

  return 1;
}

static uint8_t *
rdb_uint64_write(uint8_t *zp, uint64_t x) {
  *zp++ = (x >>  0);
  *zp++ = (x >>  8);
  *zp++ = (x >> 16);
  *zp++ = (x >> 24);
  *zp++ = (x >> 32);
  *zp++ = (x >> 40);
  *zp++ = (x >> 48);
  *zp++ = (x >> 56);
  return zp;
}

static int
rdb_uint64_read(uint64_t *zp, const uint8_t **xp, size_t *xn) {
  if (*xn < 8)
    return 0;

  *zp = ((uint64_t)(*xp)[0] <<  0)
      | ((uint64_t)(*xp)[1] <<  8)
      | ((uint64_t)(*xp)[2] << 16)
      | ((uint64_t)(*xp)[3] << 24)
      | ((uint64_t)(*xp)[4] << 32)
      | ((uint64_t)(*xp)[5] << 40)
      | ((uint64_t)(*xp)[6] << 48)
      | ((uint64_t)(*xp)[7] << 56);

  *xp += 8;
  *xn -= 8;

  return 1;
}

/*
 * Primitives
 */

struct rdb_node_s;

typedef struct rdb_internal_s {
  struct rdb_node_s *buckets[16];
} rdb_internal_t;

typedef struct rdb_leaf_s {
  uint64_t vptr;
  unsigned char *value;
  size_t size;
} rdb_leaf_t;

typedef struct rdb_node_s {
  uint8_t type;
  uint8_t flags;
  uint64_t ptr;
  uint8_t length;
  uint8_t prefix[RDB_TREE_DEPTH];
  union {
    rdb_internal_t internal;
    rdb_leaf_t leaf;
  } u;
} rdb_node_t;

static rdb_node_t rdb_null_;
static rdb_node_t *rdb_null = &rdb_null_;

#define INTERNAL(n) (&(n)->u.internal)
#define LEAF(n) (&(n)->u.leaf)
#define OFFSET(ptr) ((int64_t)((ptr) >> 16))
#define LENGTH(ptr) ((size_t)((ptr) & 0xffff))
#define PTR(off, len) (((uint64_t)(off) << 16) | (len))

static uint8_t *
rdb_nibs_write(uint8_t *zp, const uint8_t *xp, size_t xn) {
  size_t i;

  for (i = 0; i < xn - (xn & 1); i += 2)
    *zp++ = (xp[i + 0] << 4) | xp[i + 1];

  if (xn & 1)
    *zp++ = xp[xn - 1] << 4;

  return zp;
}

static void
rdb_nibs_import(uint8_t *zp, const uint8_t *xp, size_t xn) {
  size_t i;

  for (i = 0; i < xn; i++) {
    *zp++ = xp[i] >> 4;
    *zp++ = xp[i] & 15;
  }
}

static int
rdb_nibs_read(uint8_t *zp, size_t zn, const uint8_t **xp, size_t *xn) {
  size_t length = (zn + 1) / 2;

  if (*xn < length)
    return 0;

  rdb_nibs_import(zp, *xp, length);

  *xp += length;
  *xn -= length;

  return 1;
}

static size_t
rdb_node_sizeof(unsigned int type) {
  if (type == RDB_NODE_PTR)
    return offsetof(rdb_node_t, length);
  return sizeof(rdb_node_t);
}

static rdb_node_t *
rdb_node_create(unsigned int type) {
  size_t size = rdb_node_sizeof(type);
  rdb_node_t *node = rdb_malloc(size);

  memset(node, 0, size);

  node->type = type;

  return node;
}

static void
rdb_node_destroy(rdb_node_t *node, int recurse) {
  switch (node->type) {
    case RDB_NODE_NULL: {
      break;
    }

    case RDB_NODE_INTERNAL: {
      rdb_internal_t *ni = INTERNAL(node);
      int i;

      if (recurse) {
        for (i = 0; i < 16; i++)
          rdb_node_destroy(ni->buckets[i], 1);
      }

      rdb_free(node, sizeof(*node));

      break;
    }

    case RDB_NODE_LEAF: {
      rdb_leaf_t *nl = LEAF(node);

      if (nl->value != NULL)
        rdb_free(nl->value, nl->size);

      rdb_free(node, sizeof(*node));

      break;
    }

    case RDB_NODE_PTR: {
      rdb_free(node, offsetof(rdb_node_t, length));
      break;
    }
  }
}

static uint8_t *
rdb_node_write(uint8_t *zp, const rdb_node_t *node) {
  zp = rdb_uint8_write(zp, node->type);
  zp = rdb_uint8_write(zp, node->length);
  zp = rdb_nibs_write(zp, node->prefix, node->length);

  switch (node->type) {
    case RDB_NODE_INTERNAL: {
      const rdb_internal_t *ni = INTERNAL(node);
      int field = 0;
      int i;

      for (i = 0; i < 16; i++) {
        const rdb_node_t *child = ni->buckets[i];

        if (child->type == RDB_NODE_NULL)
          continue;

        field |= (1 << i);
      }

      zp = rdb_uint16_write(zp, field);

      for (i = 0; i < 16; i++) {
        const rdb_node_t *child = ni->buckets[i];

        if (child->type == RDB_NODE_NULL)
          continue;

        zp = rdb_uint64_write(zp, child->ptr);
      }

      break;
    }

    case RDB_NODE_LEAF: {
      const rdb_leaf_t *nl = LEAF(node);

      zp = rdb_uint64_write(zp, nl->vptr);

      break;
    }
  }

  return zp;
}

static size_t
rdb_node_export(uint8_t *zp, const rdb_node_t *node) {
  return rdb_node_write(zp, node) - zp;
}

static int
rdb_node_read(rdb_node_t *node, const uint8_t **xp, size_t *xn) {
  if (!rdb_uint8_read(&node->type, xp, xn))
    return 0;

  if (!rdb_uint8_read(&node->length, xp, xn))
    return 0;

  if (!rdb_nibs_read(node->prefix, node->length, xp, xn))
    return 0;

  switch (node->type) {
    case RDB_NODE_INTERNAL: {
      rdb_internal_t *ni = INTERNAL(node);
      uint16_t field;
      uint64_t ptr;
      int i;

      if (!rdb_uint16_read(&field, xp, xn))
        return 0;

      for (i = 0; i < 16; i++) {
        rdb_node_t *child = rdb_null;

        if (field & (1 << i)) {
          if (!rdb_uint64_read(&ptr, xp, xn))
            return 0;

          child = rdb_node_create(RDB_NODE_PTR);
          child->flags |= RDB_FLAG_WRITTEN;
          child->ptr = ptr;
        }

        ni->buckets[i] = child;
      }

      node->flags |= RDB_FLAG_WRITTEN;

      return 1;
    }

    case RDB_NODE_LEAF: {
      rdb_leaf_t *nl = LEAF(node);

      if (!rdb_uint64_read(&nl->vptr, xp, xn))
        return 0;

      node->flags |= RDB_FLAG_WRITTEN;
      node->flags |= RDB_FLAG_SAVED;

      return 1;
    }
  }

  return 0;
}

static int
rdb_node_import(rdb_node_t *node, const uint8_t *xp, size_t xn) {
  return rdb_node_read(node, &xp, &xn);
}

static rdb_node_t *
rdb_node_internal(const uint8_t *pp, size_t pn, rdb_node_t **buckets) {
  rdb_node_t *node = rdb_node_create(RDB_NODE_INTERNAL);
  rdb_internal_t *ni = INTERNAL(node);
  int i;

  node->length = pn;

  if (pn > 0)
    memcpy(node->prefix, pp, pn);

  if (buckets != NULL) {
    for (i = 0; i < 16; i++)
      ni->buckets[i] = buckets[i];
  } else {
    for (i = 0; i < 16; i++)
      ni->buckets[i] = rdb_null;
  }

  return node;
}

static rdb_node_t *
rdb_node_leaf(const uint8_t *pp, size_t pn, const uint8_t *vp, size_t vn) {
  rdb_node_t *node = rdb_node_create(RDB_NODE_LEAF);
  rdb_leaf_t *nl = LEAF(node);

  node->length = pn;

  if (pn > 0)
    memcpy(node->prefix, pp, pn);

  if (vn > 0) {
    nl->value = rdb_malloc(vn);

    memcpy(nl->value, vp, vn);
  }

  nl->size = vn;

  node->flags |= RDB_FLAG_VALUE;

  return node;
}

static rdb_node_t *
rdb_node_ptr(uint64_t ptr) {
  rdb_node_t *node = rdb_node_create(RDB_NODE_PTR);

  node->flags = RDB_FLAG_WRITTEN;
  node->ptr = ptr;

  return node;
}

static int
rdb_node_match(const rdb_node_t *node, const uint8_t *kp, size_t kn) {
  if (kn <= node->length)
    return 0;

  return memcmp(kp, node->prefix, node->length) == 0;
}

static int
rdb_node_equal(const rdb_node_t *node, const uint8_t *kp, size_t kn) {
  if (kn != node->length)
    return 0;

  return memcmp(kp, node->prefix, node->length) == 0;
}

static int
rdb_node_compare(const rdb_node_t *node, const uint8_t *kp, size_t kn) {
  if (kn <= node->length)
    return -1;

  return memcmp(node->prefix, kp, node->length);
}

static int
rdb_node_collide(const rdb_node_t *node, const uint8_t *kp, size_t kn) {
  const uint8_t *pp = node->prefix;
  size_t pn = node->length;
  size_t n = kn < pn ? kn : pn;
  size_t i;

  for (i = 0; i < n; i++) {
    if (pp[i] != kp[i])
      return i;
  }

  return n;
}

static int
rdb_value_equal(const rdb_node_t *node, const uint8_t *vp, size_t vn) {
  const rdb_leaf_t *nl = LEAF(node);

  if (!(node->flags & RDB_FLAG_VALUE))
    return 0;

  if (nl->size != vn)
    return 0;

  if (nl->size == 0)
    return 1;

  return memcmp(nl->value, vp, vn) == 0;
}

static rdb_node_t *
rdb_value_set(rdb_node_t *node, const uint8_t *vp, size_t vn) {
  rdb_leaf_t *nl = LEAF(node);

  if (vn > 0) {
    if (vn > nl->size)
      nl->value = rdb_realloc(nl->value, nl->size, vn);

    memcpy(nl->value, vp, vn);
  }

  nl->size = vn;

  node->flags |= RDB_FLAG_VALUE;
  node->flags &= ~RDB_FLAG_WRITTEN;
  node->flags &= ~RDB_FLAG_SAVED;

  return node;
}

/*
 * Checksum
 */

static uint8_t *
rdb_checksum(uint8_t *zp, const uint8_t *xp, size_t xn, const uint8_t *key) {
  rdb_sha256(zp, xp, xn, key, 20);
  return zp + 20;
}

/*
 * Meta Page
 */

typedef struct rdb_meta_s {
  uint64_t meta_ptr;
  uint64_t root_ptr;
  uint64_t compact;
} rdb_meta_t;

static void
rdb_meta_init(rdb_meta_t *meta) {
  memset(meta, 0, sizeof(*meta));
}

static uint8_t *
rdb_meta_write(uint8_t *zp, const rdb_meta_t *meta, const uint8_t *key) {
  uint8_t *sp = zp;

  zp = rdb_uint32_write(zp, RDB_MAGIC);
  zp = rdb_uint64_write(zp, meta->meta_ptr);
  zp = rdb_uint64_write(zp, meta->root_ptr);
  zp = rdb_uint64_write(zp, meta->compact);
  zp = rdb_checksum(zp, sp, zp - sp, key);

  return zp;
}

static int
rdb_meta_read(rdb_meta_t *meta,
              const uint8_t **xp,
              size_t *xn,
              const uint8_t *key) {
  const uint8_t *sp = *xp;
  uint8_t chk[20];
  uint32_t magic;

  if (!rdb_uint32_read(&magic, xp, xn))
    return 0;

  if (magic != RDB_MAGIC)
    return 0;

  if (!rdb_uint64_read(&meta->meta_ptr, xp, xn))
    return 0;

  if (!rdb_uint64_read(&meta->root_ptr, xp, xn))
    return 0;

  if (!rdb_uint64_read(&meta->compact, xp, xn))
    return 0;

  rdb_checksum(chk, sp, *xp - sp, key);

  if (*xn < 20)
    return 0;

  if (memcmp(*xp, chk, 20) != 0)
    return 0;

  *xp += 20;
  *xn -= 20;

  return 1;
}

static int
rdb_meta_import(rdb_meta_t *meta, const uint8_t *xp, const uint8_t *key) {
  size_t xn = RDB_META_SIZE;
  return rdb_meta_read(meta, &xp, &xn, key);
}

/*
 * Write Buffer
 */

typedef struct rdb_slab_s {
  unsigned char *data; /* Preallocated slab. */
  size_t alloc; /* Total bytes allocated. */
  size_t length; /* Total bytes written. */
  uint64_t position; /* Current file position. */
} rdb_slab_t;

static void
rdb_slab_init(rdb_slab_t *slab) {
  memset(slab, 0, sizeof(*slab));

  slab->data = rdb_malloc(8192);
  slab->alloc = 8192;
}

static void
rdb_slab_clear(rdb_slab_t *slab) {
  if (slab->data != NULL)
    rdb_free(slab->data, slab->alloc);
}

static void
rdb_slab_write(rdb_slab_t *slab, const unsigned char *data, size_t size) {
  while (slab->length + size > slab->alloc) {
    size_t alloc = (slab->alloc * 3) / 2;
    slab->data = rdb_realloc(slab->data, slab->alloc, alloc);
    slab->alloc = alloc;
  }

  if (size > 0)
    memcpy(slab->data + slab->length, data, size);

  slab->length += size;
  slab->position += size;
}

/*
 * Tree
 */

struct rdb_s {
  char path[RDB_PATH_MAX - 14];
  unsigned int flags;
  unsigned int mode;
  rdb_slab_t slab;
  rdb_meta_t state;
  int lfd, fd;
  uint8_t key[20];
#ifdef RDB_MMAP
  void *base;
  size_t size;
#endif
  rdb_txn_t *head;
  rdb_txn_t *tail;
#ifdef RDB_BACKGROUND_COMPACTION
  pthread_mutex_t mutex;
  pthread_cond_t master;
  pthread_cond_t worker;
  rdb_node_t *snapshot;
  int compacting;
  int done;
  int stop;
#endif
};

#ifdef RDB_BACKGROUND_COMPACTION
typedef struct rdb_update_s {
  int type;
  uint8_t kp[RDB_TREE_DEPTH];
  size_t kl; /* future proofing */
  uint8_t *vp;
  size_t vn;
  struct rdb_update_s *next;
} rdb_update_t;
#endif

struct rdb_txn_s {
  rdb_t *tree;
  rdb_node_t *root;
#ifndef RDB_MMAP
  uint8_t buf[RDB_VALUE_SIZE];
#endif
  rdb_txn_t *prev;
  rdb_txn_t *next;
#ifdef RDB_BACKGROUND_COMPACTION
  rdb_update_t *head;
  rdb_update_t *tail;
#endif
};

static void
rdb_tree_init(rdb_t *tree) {
  memset(tree, 0, sizeof(*tree));

  rdb_slab_init(&tree->slab);

#ifdef RDB_BACKGROUND_COMPACTION
  CHECK(pthread_mutex_init(&tree->mutex, NULL) == 0);
  CHECK(pthread_cond_init(&tree->master, NULL) == 0);
  CHECK(pthread_cond_init(&tree->worker, NULL) == 0);
#endif
}

static void
rdb_tree_clear(rdb_t *tree) {
  CHECK(tree->head == NULL);
  CHECK(tree->tail == NULL);

  rdb_slab_clear(&tree->slab);

#ifdef RDB_BACKGROUND_COMPACTION
  CHECK(pthread_mutex_destroy(&tree->mutex) == 0);
  CHECK(pthread_cond_destroy(&tree->master) == 0);
  CHECK(pthread_cond_destroy(&tree->worker) == 0);
#endif
}

#ifdef RDB_BACKGROUND_COMPACTION
static void *
compact_thread(void *arg);
#endif

static int
rdb_recover(rdb_meta_t *meta, int fd, const uint8_t *key) {
  uint8_t *slab = rdb_malloc(RDB_SLAB_SIZE);
  struct stat st;
  int64_t off;
  int ret = 0;

  rdb_meta_init(meta);

  if (fstat(fd, &st) == -1)
    goto done;

  off = st.st_size - (st.st_size % RDB_META_SIZE);

  while (off >= RDB_META_SIZE) {
    int64_t pos = 0;
    int64_t size = off;

    if (off >= RDB_SLAB_SIZE) {
      pos = off - RDB_SLAB_SIZE;
      size = RDB_SLAB_SIZE;
    }

    if (!safe_pread(fd, slab, size, pos))
      goto done;

    while (size >= RDB_META_SIZE) {
      size -= RDB_META_SIZE;
      off -= RDB_META_SIZE;

      if (rdb_meta_import(meta, slab + size, key)) {
        ftruncate(fd, off + RDB_META_SIZE);
        ret = 1;
        goto done;
      }
    }
  }

done:
  rdb_free(slab, RDB_SLAB_SIZE);
  return ret;
}

static int
rdb_tree_open(rdb_t *tree,
              const char *file,
              unsigned int flags,
              unsigned int mode) {
  size_t flen = strlen(file);
  char path[RDB_PATH_MAX];
  rdb_meta_t state;
  uint8_t key[20];
  struct stat st;
  int oflags = 0;
  int lfd = -1;
  int fd = -1;
#ifdef RDB_MMAP
  size_t size;
  void *base;
#endif

  if (flen + 14 > RDB_PATH_MAX)
    return RDB_EINVAL;

  sprintf(path, "%s-lock", file);

  if (flags & RDB_RDWR) {
    if ((lfd = open_lock(path, 0644)) == -1)
      return RDB_EBADOPEN;

    oflags = O_RDWR | O_APPEND;

    if (flags & RDB_CREATE)
      oflags |= O_CREAT;
  } else {
    oflags = O_RDONLY;
  }

#ifdef O_RANDOM
  oflags |= O_RANDOM;
#endif

  if ((fd = safe_open(file, oflags, mode)) == -1)
    goto fail;

  if (fstat(fd, &st) == -1)
    goto fail;

  if (st.st_size < 20 && !(flags & RDB_RDWR))
    goto fail;

  if (st.st_size == 0) {
    if (!random_key(key))
      goto fail;

    if (!safe_write(fd, key, 20))
      goto fail;

    if (fsync(fd) == -1)
      goto fail;
  } else {
    if (st.st_size < 20) {
      ftruncate(fd, 0);
      goto fail;
    }

    if (!safe_pread(fd, key, 20, 0))
      goto fail;
  }

  if (st.st_size > 20) {
    if (!rdb_recover(&state, fd, key))
      goto fail;
  } else {
    rdb_meta_init(&state);
  }

  if (fstat(fd, &st) == -1)
    goto fail;

#ifdef RDB_MMAP
  size = (st.st_size * 3) / 2;
  base = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);

  if (base == MAP_FAILED)
    goto fail;
#endif

  sprintf(path, "%s-compact-lock", file);
  unlink(path);

  sprintf(path, "%s-compact", file);
  unlink(path);

  memmove(tree->path, file, flen + 1);

  tree->flags = flags;
  tree->mode = mode;
  tree->slab.length = 0;
  tree->slab.position = st.st_size;
  tree->state = state;
  tree->lfd = lfd;
  tree->fd = fd;

  memcpy(tree->key, key, 20);

#ifdef RDB_MMAP
  tree->base = base;
  tree->size = size;
#endif

#ifdef RDB_BACKGROUND_COMPACTION
  if (!(tree->flags & RDB_NOTHREADS)) {
    pthread_t thread;

    tree->snapshot = NULL;
    tree->compacting = 0;
    tree->done = 0;
    tree->stop = 0;

    pthread_create(&thread, NULL, compact_thread, tree);
    pthread_detach(thread);
  }
#endif

  return RDB_OK;
fail:
  if (fd != -1)
    close(fd);

  if (lfd != -1) {
    close_lock(lfd);
    unlink(path);
  }

  return RDB_EBADOPEN;
}

static int
rdb_tree_close(rdb_t *tree) {
  char path[RDB_PATH_MAX];
  int rc = RDB_OK;

#ifdef RDB_BACKGROUND_COMPACTION
  if (!(tree->flags & RDB_NOTHREADS)) {
    CHECK(pthread_mutex_lock(&tree->mutex) == 0);

    tree->stop = 1;

    CHECK(pthread_cond_signal(&tree->worker) == 0);
    CHECK(pthread_cond_wait(&tree->master, &tree->mutex) == 0);
    CHECK(tree->stop == 0);

    CHECK(pthread_mutex_unlock(&tree->mutex) == 0);
  }
#endif

#ifdef RDB_MMAP
  if (munmap(tree->base, tree->size) == -1)
    rc = RDB_EBADCLOSE;
#endif

  if (tree->flags & RDB_RDWR) {
    if (fsync(tree->fd) == -1)
      rc = RDB_EBADCLOSE;
  }

  if (close(tree->fd) == -1)
    rc = RDB_EBADCLOSE;

  if (tree->flags & RDB_RDWR) {
    if (close_lock(tree->lfd) == -1)
      rc = RDB_EBADCLOSE;

    sprintf(path, "%s-lock", tree->path);

    if (unlink(path) == -1)
      rc = RDB_EBADCLOSE;
  }

  tree->fd = -1;
  tree->lfd = -1;

  tree->slab.length = 0;
  tree->slab.position = 0;

  return rc;
}

static int
rdb_read_node(rdb_t *tree, rdb_node_t *out, uint64_t ptr) {
  int64_t offset = OFFSET(ptr);
  size_t length = LENGTH(ptr);
#ifndef RDB_MMAP
  uint8_t data[RDB_NODE_SIZE];
#endif

  if (length == 0 || length > RDB_NODE_SIZE)
    return 0;

#ifndef RDB_MMAP
  if (!safe_pread(tree->fd, data, length, offset))
    return 0;

  if (!rdb_node_import(out, data, length))
    return 0;
#else
  if (!rdb_node_import(out, (uint8_t *)tree->base + offset, length))
    return 0;
#endif

  out->ptr = ptr;
  out->flags |= RDB_FLAG_WRITTEN;

  return 1;
}

static rdb_node_t *
rdb_resolve(rdb_t *tree, const rdb_node_t *node) {
  rdb_node_t *out = rdb_node_create(0);

  CHECK(node->type == RDB_NODE_PTR);

  if (!rdb_read_node(tree, out, node->ptr)) {
    rdb_node_destroy(out, 1);
    return NULL;
  }

  return out;
}

#ifdef RDB_MMAP
typedef const uint8_t **rdb_val_t;
#else
typedef uint8_t *rdb_val_t;
#endif

static int
rdb_retrieve(rdb_t *tree, const rdb_node_t *node, rdb_val_t vp, size_t *vn) {
  const rdb_leaf_t *leaf = LEAF(node);
  int64_t offset = OFFSET(leaf->vptr);
  size_t length = LENGTH(leaf->vptr);

  CHECK(node->type == RDB_NODE_LEAF);

  if (node->flags & RDB_FLAG_VALUE) {
    CHECK(leaf->size <= RDB_VALUE_SIZE);

#ifndef RDB_MMAP
    if (leaf->size > 0)
      memcpy(vp, leaf->value, leaf->size);
#else
    *vp = leaf->value;
#endif

    *vn = leaf->size;

    return 1;
  }

  CHECK(node->flags & RDB_FLAG_SAVED);

  if (length > RDB_VALUE_SIZE)
    return 0;

#ifndef RDB_MMAP
  if (!safe_pread(tree->fd, vp, length, offset))
    return 0;
#else
  *vp = (uint8_t *)tree->base + offset;
#endif

  *vn = length;

  return 1;
}

static void
rdb_write_node(rdb_t *tree, rdb_node_t *node) {
  rdb_slab_t *slab = &tree->slab;
  uint8_t raw[RDB_NODE_SIZE];
  size_t size = rdb_node_export(raw, node);

  CHECK(node->type == RDB_NODE_INTERNAL
     || node->type == RDB_NODE_LEAF);

  CHECK(!(node->flags & RDB_FLAG_WRITTEN));

  rdb_slab_write(slab, raw, size);

  node->ptr = PTR(slab->position - size, size);
  node->flags |= RDB_FLAG_WRITTEN;
}

static void
rdb_write_value(rdb_t *tree, rdb_node_t *node) {
  rdb_slab_t *slab = &tree->slab;
  rdb_leaf_t *leaf = LEAF(node);

  CHECK(node->type == RDB_NODE_LEAF);
  CHECK(!(node->flags & RDB_FLAG_SAVED));
  CHECK(node->flags & RDB_FLAG_VALUE);

  rdb_slab_write(slab, leaf->value, leaf->size);

  leaf->vptr = PTR(slab->position - leaf->size, leaf->size);

  node->flags |= RDB_FLAG_SAVED;
}

static int
rdb_needs_flush(const rdb_t *tree) {
  return tree->slab.length >= RDB_WRITE_BUFFER;
}

static int
rdb_flush(rdb_t *tree) {
  rdb_slab_t *slab = &tree->slab;

  if (!safe_write(tree->fd, slab->data, slab->length))
    return 0;

#ifdef RDB_MMAP
  if (slab->position > tree->size) {
    if (munmap(tree->base, tree->size) == -1)
      return 0;

    tree->size = (slab->position * 3) / 2;
    tree->base = mmap(NULL, tree->size, PROT_READ, MAP_SHARED, tree->fd, 0);

    if (tree->base == MAP_FAILED)
      return 0;
  }
#endif

  slab->length = 0;

  return 1;
}

static void
rdb_write_meta(rdb_t *tree,
               rdb_meta_t *state,
               const rdb_node_t *root,
               int compact) {
  static const uint8_t padding[RDB_META_SIZE] = {0};
  rdb_slab_t *slab = &tree->slab;
  uint8_t raw[RDB_META_SIZE];

  *state = tree->state;

  state->root_ptr = root->ptr;

  if (slab->position % RDB_META_SIZE) {
    size_t size = RDB_META_SIZE - (slab->position % RDB_META_SIZE);

    rdb_slab_write(slab, padding, size);
  }

  if (compact)
    state->compact = slab->position + RDB_META_SIZE;

  rdb_meta_write(raw, state, tree->key);
  rdb_slab_write(slab, raw, RDB_META_SIZE);

  state->meta_ptr = PTR(slab->position - RDB_META_SIZE, RDB_META_SIZE);
}

static int
rdb_commit(rdb_t *tree, const rdb_node_t *root, int compact) {
  rdb_meta_t state;

  rdb_write_meta(tree, &state, root, compact);

  if (!rdb_flush(tree))
    return RDB_EBADWRITE;

  tree->state = state;

  return RDB_OK;
}

static int
rdb_tree_get(rdb_t *tree,
             rdb_val_t vp,
             size_t *vn,
             const rdb_node_t *node,
             const uint8_t *kp,
             size_t kn) {
  switch (node->type) {
    case RDB_NODE_NULL: {
      return RDB_ENOTFOUND;
    }

    case RDB_NODE_INTERNAL: {
      const rdb_internal_t *ni = INTERNAL(node);

      if (!rdb_node_match(node, kp, kn))
        return RDB_ENOTFOUND;

      kp += node->length;
      kn -= node->length;
      node = ni->buckets[kp[0]];

      return rdb_tree_get(tree, vp, vn, node, kp + 1, kn - 1);
    }

    case RDB_NODE_LEAF: {
      if (!rdb_node_equal(node, kp, kn))
        return RDB_ENOTFOUND;

      if (vp != NULL && vn != NULL) {
        if (!rdb_retrieve(tree, node, vp, vn))
          return RDB_ECORRUPTION;
      }

      return RDB_OK;
    }

    case RDB_NODE_PTR: {
      rdb_node_t *rn = rdb_resolve(tree, node);
      int rc;

      if (rn == NULL)
        return RDB_ECORRUPTION;

      rc = rdb_tree_get(tree, vp, vn, rn, kp, kn);

      rdb_node_destroy(rn, 1);

      return rc;
    }

    default: {
      abort();
      return RDB_EINVAL;
    }
  }
}

static int
rdb_tree_put(rdb_t *tree,
             rdb_node_t **pnode,
             const uint8_t *kp,
             size_t kn,
             const uint8_t *vp,
             size_t vn) {
  rdb_node_t *node = *pnode;

  switch (node->type) {
    case RDB_NODE_NULL: {
      rdb_node_destroy(node, 0);

      *pnode = rdb_node_leaf(kp, kn, vp, vn);

      return RDB_OK;
    }

    case RDB_NODE_INTERNAL: {
      const uint8_t *pp = node->prefix;
      size_t pn = node->length;
      int count = rdb_node_collide(node, kp, kn);
      rdb_internal_t *ni = INTERNAL(node);
      rdb_node_t *x;
      int i, rc;

      pp += count;
      pn -= count;
      kp += count;
      kn -= count;

      CHECK(kn != 0);

      if (pn != 0) {
        rdb_node_t *child = rdb_node_internal(pp + 1, pn - 1, ni->buckets);
        rdb_node_t *leaf = rdb_node_leaf(kp + 1, kn - 1, vp, vn);

        for (i = 0; i < 16; i++)
          ni->buckets[i] = rdb_null;

        ni->buckets[pp[0]] = child;
        ni->buckets[kp[0]] = leaf;

        node->length = count;
        node->flags &= ~RDB_FLAG_WRITTEN;

        return RDB_OK;
      }

      x = ni->buckets[kp[0]];
      rc = rdb_tree_put(tree, &x, kp + 1, kn - 1, vp, vn);

      if (rc != RDB_OK)
        return rc;

      ni->buckets[kp[0]] = x;

      node->flags &= ~RDB_FLAG_WRITTEN;

      return RDB_OK;
    }

    case RDB_NODE_LEAF: {
      const uint8_t *pp = node->prefix;
      size_t pn = node->length;
      rdb_node_t *out, *leaf;
      int count;

      if (rdb_node_equal(node, kp, kn)) {
        if (rdb_value_equal(node, vp, vn))
          return RDB_ENOUPDATE;

        rdb_value_set(node, vp, vn);

        return RDB_OK;
      }

      count = rdb_node_collide(node, kp, kn);

      pp += count;
      pn -= count;
      kp += count;
      kn -= count;

      CHECK(kn != 0);
      CHECK(pn != 0);

      out = rdb_node_internal(node->prefix, count, NULL);
      leaf = rdb_node_leaf(kp + 1, kn - 1, vp, vn);

      INTERNAL(out)->buckets[pp[0]] = node;
      INTERNAL(out)->buckets[kp[0]] = leaf;

      memmove(node->prefix, pp + 1, pn - 1);

      node->length = pn - 1;
      node->flags &= ~RDB_FLAG_WRITTEN;

      *pnode = out;

      return RDB_OK;
    }

    case RDB_NODE_PTR: {
      rdb_node_t *rn = rdb_resolve(tree, node);
      int rc;

      if (rn == NULL)
        return RDB_ECORRUPTION;

      rc = rdb_tree_put(tree, &rn, kp, kn, vp, vn);

      if (rc != RDB_OK) {
        rdb_node_destroy(rn, 1);
        return rc;
      }

      rdb_node_destroy(node, 0);

      *pnode = rn;

      return RDB_OK;
    }

    default: {
      abort();
      return RDB_EINVAL;
    }
  }
}

static int
rdb_tree_del(rdb_t *tree, rdb_node_t **pnode, const uint8_t *kp, size_t kn) {
  rdb_node_t *node = *pnode;

  switch (node->type) {
    case RDB_NODE_NULL: {
      return RDB_ENOTFOUND;
    }

    case RDB_NODE_INTERNAL: {
      rdb_internal_t *ni = INTERNAL(node);
      rdb_node_t *side = NULL;
      rdb_node_t *x;
      int total = 0;
      int index = 0;
      int i, rc;

      if (!rdb_node_match(node, kp, kn))
        return RDB_ENOTFOUND;

      kp += node->length;
      kn -= node->length;

      x = ni->buckets[kp[0]];
      rc = rdb_tree_del(tree, &x, kp + 1, kn - 1);

      if (rc != RDB_OK)
        return rc;

      ni->buckets[kp[0]] = x;

      for (i = 0; i < 16; i++) {
        if (ni->buckets[i]->type != RDB_NODE_NULL) {
          side = ni->buckets[i];
          index = i;
          total += 1;
        }
      }

      if (total == 1) {
        uint8_t xp[RDB_TREE_DEPTH];
        uint8_t *zp = xp;
        int resolved = 0;

        if (side->type == RDB_NODE_PTR) {
          side = rdb_resolve(tree, side);

          if (side == NULL)
            return RDB_ECORRUPTION;

          resolved = 1;
        }

        for (i = 0; i < node->length; i++)
          *zp++ = node->prefix[i];

        *zp++ = index;

        for (i = 0; i < side->length; i++)
          *zp++ = side->prefix[i];

        memcpy(side->prefix, xp, zp - xp);

        side->length = zp - xp;
        side->flags &= ~RDB_FLAG_WRITTEN;

        rdb_node_destroy(node, resolved);
        rdb_node_destroy(x, 0);

        *pnode = side;

        return RDB_OK;
      }

      CHECK(total != 0);

      node->flags &= ~RDB_FLAG_WRITTEN;

      return RDB_OK;
    }

    case RDB_NODE_LEAF: {
      if (!rdb_node_equal(node, kp, kn))
        return RDB_ENOTFOUND;

      rdb_node_destroy(node, 0);

      *pnode = rdb_null;

      return RDB_OK;
    }

    case RDB_NODE_PTR: {
      rdb_node_t *rn = rdb_resolve(tree, node);
      int rc;

      if (rn == NULL)
        return RDB_ECORRUPTION;

      rc = rdb_tree_del(tree, &rn, kp, kn);

      if (rc != RDB_OK) {
        rdb_node_destroy(rn, 1);
        return rc;
      }

      rdb_node_destroy(node, 0);

      *pnode = rn;

      return RDB_OK;
    }

    default: {
      abort();
      return RDB_EINVAL;
    }
  }
}

static int
rdb_tree_write(rdb_t *tree, rdb_node_t **pnode) {
  rdb_node_t *node = *pnode;

  switch (node->type) {
    case RDB_NODE_NULL: {
      return RDB_OK;
    }

    case RDB_NODE_INTERNAL: {
      rdb_internal_t *ni = INTERNAL(node);
      int i;

      for (i = 0; i < 16; i++) {
        rdb_node_t *child = ni->buckets[i];
        int rc = rdb_tree_write(tree, &child);

        if (rc != RDB_OK)
          return rc;

        ni->buckets[i] = child;
      }

      if (!(node->flags & RDB_FLAG_WRITTEN)) {
        rdb_write_node(tree, node);

        if (rdb_needs_flush(tree)) {
          if (!rdb_flush(tree))
            return RDB_EBADWRITE;
        }
      }

      *pnode = rdb_node_ptr(node->ptr);

      rdb_node_destroy(node, 1);

      return RDB_OK;
    }

    case RDB_NODE_LEAF: {
      if (!(node->flags & RDB_FLAG_WRITTEN)) {
        if (!(node->flags & RDB_FLAG_SAVED))
          rdb_write_value(tree, node);

        rdb_write_node(tree, node);

        if (rdb_needs_flush(tree)) {
          if (!rdb_flush(tree))
            return RDB_EBADWRITE;
        }
      }

      *pnode = rdb_node_ptr(node->ptr);

      rdb_node_destroy(node, 1);

      return RDB_OK;
    }

    case RDB_NODE_PTR: {
      CHECK(node->flags & RDB_FLAG_WRITTEN);
      return RDB_OK;
    }

    default: {
      abort();
      return RDB_EINVAL;
    }
  }
}

static int
rdb_tree_commit(rdb_t *tree, rdb_node_t **root) {
  int rc;

  if ((rc = rdb_tree_write(tree, root)))
    return rc;

#ifdef __GLIBC__
  malloc_trim(0);
#endif

  return rdb_commit(tree, *root, 0);
}

static rdb_node_t *
rdb_snapshot(rdb_t *tree) {
  if (tree->state.root_ptr == 0)
    return rdb_null;

  return rdb_node_ptr(tree->state.root_ptr);
}

static int
rdb_tree_rewrite(rdb_t *tree, rdb_t *ntree, rdb_node_t **pnode) {
  rdb_node_t *node = *pnode;

  switch (node->type) {
    case RDB_NODE_NULL: {
      return RDB_OK;
    }

    case RDB_NODE_INTERNAL: {
      rdb_internal_t *ni = INTERNAL(node);
      int i;

      for (i = 0; i < 16; i++) {
        rdb_node_t *child = ni->buckets[i];
        int rc = rdb_tree_rewrite(tree, ntree, &child);

        if (rc != RDB_OK)
          return rc;

        ni->buckets[i] = child;
      }

      node->flags &= ~RDB_FLAG_WRITTEN;

      rdb_write_node(ntree, node);

      if (rdb_needs_flush(ntree)) {
        if (!rdb_flush(ntree))
          return RDB_EBADWRITE;
      }

      *pnode = rdb_node_ptr(node->ptr);

      rdb_node_destroy(node, 1);

      return RDB_OK;
    }

    case RDB_NODE_LEAF: {
      if (!(node->flags & RDB_FLAG_VALUE)) {
        const uint8_t *vp;
        size_t vn;

#ifndef RDB_MMAP
        uint8_t buf[RDB_VALUE_SIZE];

        if (!rdb_retrieve(tree, node, buf, &vn))
          return RDB_ECORRUPTION;

        vp = buf;
#else
        if (!rdb_retrieve(tree, node, &vp, &vn))
          return RDB_ECORRUPTION;
#endif

        rdb_value_set(node, vp, vn);
      }

      node->flags &= ~RDB_FLAG_WRITTEN;
      node->flags &= ~RDB_FLAG_SAVED;

      rdb_write_value(ntree, node);
      rdb_write_node(ntree, node);

      if (rdb_needs_flush(ntree)) {
        if (!rdb_flush(ntree))
          return RDB_EBADWRITE;
      }

      *pnode = rdb_node_ptr(node->ptr);

      rdb_node_destroy(node, 1);

      return RDB_OK;
    }

    case RDB_NODE_PTR: {
      rdb_node_t *rn = rdb_resolve(tree, node);
      int rc;

      if (rn == NULL)
        return RDB_ECORRUPTION;

      rc = rdb_tree_rewrite(tree, ntree, &rn);

      if (rc != RDB_OK) {
        rdb_node_destroy(rn, 1);
        return rc;
      }

      rdb_node_destroy(node, 0);

      *pnode = rn;

      return RDB_OK;
    }

    default: {
      abort();
      return RDB_EINVAL;
    }
  }
}

static int
rdb_tree_dump(rdb_t *tree, rdb_node_t *root) {
  unsigned int flags = tree->flags | RDB_CREATE | RDB_NOTHREADS;
  unsigned int mode = tree->mode;
  char file[RDB_PATH_MAX];
  rdb_t ntree;
  int rc;

  sprintf(file, "%s-compact", tree->path);

  rdb_tree_init(&ntree);

  if (!(tree->flags & RDB_CREATE))
    mode = 0644;

  if ((rc = rdb_tree_open(&ntree, file, flags, mode))) {
    rdb_node_destroy(root, 1);
    rdb_tree_clear(&ntree);
    return rc;
  }

  if ((rc = rdb_tree_rewrite(tree, &ntree, &root)))
    goto fail;

#ifdef __GLIBC__
  malloc_trim(0);
#endif

  if ((rc = rdb_commit(&ntree, root, 1)))
    goto fail;

  rdb_node_destroy(root, 0);

  rdb_tree_close(&ntree);
  rdb_tree_clear(&ntree);

  return RDB_OK;
fail:
  rdb_node_destroy(root, 1);
  rdb_tree_close(&ntree);
  rdb_tree_clear(&ntree);
  unlink(file);
  return rc;
}

static int
rdb_tree_reopen(rdb_t *tree) {
  unsigned int flags = tree->flags;
  char file[RDB_PATH_MAX];
  int rc = RDB_OK;
  rdb_txn_t *tx;

  sprintf(file, "%s-compact", tree->path);

  tree->flags |= RDB_NOTHREADS;
  tree->flags &= ~RDB_CREATE;

  CHECK(rdb_tree_close(tree) == RDB_OK);

  if (rename(file, tree->path) == -1) {
    CHECK(rdb_tree_open(tree, tree->path,
                              tree->flags,
                              tree->mode) == RDB_OK);
    rc = RDB_EBADWRITE;
    goto done;
  }

  rc = rdb_tree_open(tree, tree->path,
                           tree->flags,
                           tree->mode);

  if (rc != RDB_OK)
    goto done;

  for (tx = tree->head; tx != NULL; tx = tx->next)
    rdb_txn_reset(tx);

done:
  tree->flags = flags;
  return rc;
}

static int
rdb_tree_compact(rdb_t *tree) {
  rdb_node_t *root = rdb_snapshot(tree);
  int rc;

  if ((rc = rdb_tree_dump(tree, root)))
    return rc;

  if ((rc = rdb_tree_reopen(tree)))
    return rc;

  return RDB_OK;
}

static int
rdb_needs_compact(rdb_t *tree) {
  const rdb_slab_t *slab = &tree->slab;
  const rdb_meta_t *state = &tree->state;
  uint64_t size = slab->position - slab->length;

  return size >= state->compact + RDB_COMPACT_THRESH;
}

/*
 * Database
 */

rdb_t *
rdb_create(void) {
  rdb_t *db = rdb_malloc(sizeof(rdb_t));
  rdb_tree_init(db);
  return db;
}

void
rdb_destroy(rdb_t *db) {
  rdb_tree_clear(db);
  rdb_free(db, sizeof(*db));
}

int
rdb_open(rdb_t *db, const char *file, unsigned int flags, unsigned int mode) {
  return rdb_tree_open(db, file, flags, mode);
}

int
rdb_close(rdb_t *db) {
  return rdb_tree_close(db);
}

int
rdb_compact(rdb_t *db) {
  return rdb_tree_compact(db);
}

int
rdb_fd(rdb_t *db) {
  return db->fd;
}

int
rdb_sync(rdb_t *db) {
  if (!(db->flags & RDB_RDWR))
    return RDB_EINVAL;

  if (fsync(db->fd) == -1)
    return RDB_EBADWRITE;

  return RDB_OK;
}

/*
 * Transaction
 */

rdb_txn_t *
rdb_txn_create(rdb_t *db) {
  rdb_txn_t *tx = rdb_malloc(sizeof(rdb_txn_t));

  tx->tree = db;
  tx->root = rdb_snapshot(db);
  tx->prev = NULL;
  tx->next = NULL;
#ifdef RDB_BACKGROUND_COMPACTION
  tx->head = NULL;
  tx->tail = NULL;
#endif

  if (db->head == NULL)
    db->head = tx;

  if (db->tail != NULL) {
    db->tail->next = tx;
    tx->prev = db->tail;
  }

  db->tail = tx;

  return tx;
}

#ifdef RDB_BACKGROUND_COMPACTION
static void
rdb_txn_push(rdb_txn_t *tx,
             int type,
             const uint8_t *kp,
             size_t kl,
             const uint8_t *vp,
             size_t vn) {
  rdb_update_t *up = rdb_malloc(sizeof(rdb_update_t));

  up->type = type;
  up->kl = kl; /* future proofing */
  up->vp = NULL;
  up->vn = 0;
  up->next = NULL;

  memcpy(up->kp, kp, RDB_TREE_DEPTH);

  if (vn > 0) {
    up->vp = memcpy(rdb_malloc(vn), vp, vn);
    up->vn = vn;
  }

  if (tx->head == NULL)
    tx->head = up;

  if (tx->tail != NULL)
    tx->tail->next = up;

  tx->tail = up;
}

static int
rdb_txn_merge(rdb_txn_t *tx) {
  size_t kn = RDB_TREE_DEPTH;
  rdb_t *tree = tx->tree;
  rdb_update_t *up, *next;
  int rc = RDB_OK;

  for (up = tx->head; up != NULL; up = next) {
    next = up->next;

    if (rc == RDB_OK) {
      if (up->type == 0)
        rc = rdb_tree_put(tree, &tx->root, up->kp, kn, up->vp, up->vn);
      else
        rc = rdb_tree_del(tree, &tx->root, up->kp, kn);
    }

    if (up->vp != NULL)
      rdb_free(up->vp, up->vn);

    rdb_free(up, sizeof(*up));
  }

  tx->head = NULL;
  tx->tail = NULL;

  return rc;
}

static void
rdb_txn_drop(rdb_txn_t *tx) {
  rdb_update_t *up, *next;

  for (up = tx->head; up != NULL; up = next) {
    next = up->next;

    if (up->vp != NULL)
      rdb_free(up->vp, up->vn);

    rdb_free(up, sizeof(*up));
  }

  tx->head = NULL;
  tx->tail = NULL;
}
#endif /* RDB_BACKGROUND_COMPACTION */

void
rdb_txn_destroy(rdb_txn_t *tx) {
  rdb_t *tree = tx->tree;

  if (tx->prev != NULL)
    tx->prev->next = tx->next;

  if (tx->next != NULL)
    tx->next->prev = tx->prev;

  if (tx == tree->head)
    tree->head = tx->next;

  if (tx == tree->tail)
    tree->tail = tx->prev;

#ifdef RDB_BACKGROUND_COMPACTION
  rdb_txn_drop(tx);
#endif

  rdb_node_destroy(tx->root, 1);

  rdb_free(tx, sizeof(*tx));
}

void
rdb_txn_reset(rdb_txn_t *tx) {
  rdb_node_destroy(tx->root, 1);

  tx->root = rdb_snapshot(tx->tree);
}

static void
rdb_convert(uint8_t *zp, const uint8_t *xp, size_t xn) {
  memset(zp, 0, RDB_TREE_DEPTH);
  rdb_nibs_import(zp, xp, xn);
}

int
rdb_txn_get(rdb_txn_t *tx,
            const unsigned char **value,
            size_t *size,
            const unsigned char *key,
            size_t length) {
  uint8_t kp[RDB_TREE_DEPTH];
  size_t kn = sizeof(kp);

  if (length == 0 || length > RDB_KEY_SIZE)
    return RDB_EINVAL;

  rdb_convert(kp, key, length);

#ifndef RDB_MMAP
  *value = tx->buf;

  return rdb_tree_get(tx->tree, tx->buf, size, tx->root, kp, kn);
#else
  return rdb_tree_get(tx->tree, value, size, tx->root, kp, kn);
#endif
}

int
rdb_txn_has(rdb_txn_t *tx, const unsigned char *key, size_t length) {
  uint8_t kp[RDB_TREE_DEPTH];
  size_t kn = sizeof(kp);

  if (length == 0 || length > RDB_KEY_SIZE)
    return RDB_EINVAL;

  rdb_convert(kp, key, length);

  return rdb_tree_get(tx->tree, NULL, NULL, tx->root, kp, kn);
}

int
rdb_txn_put(rdb_txn_t *tx,
            const unsigned char *key,
            size_t length,
            const unsigned char *value,
            size_t size) {
  uint8_t kp[RDB_TREE_DEPTH];
  size_t kn = sizeof(kp);
  int rc;

  if (length == 0 || length > RDB_KEY_SIZE)
    return RDB_EINVAL;

  if (size == 0 || size > RDB_VALUE_SIZE)
    return RDB_EINVAL;

  rdb_convert(kp, key, length);

  rc = rdb_tree_put(tx->tree, &tx->root, kp, kn, value, size);

  if (rc == RDB_ENOUPDATE)
    return RDB_OK;

  if (rc != RDB_OK)
    return rc;

#ifdef RDB_BACKGROUND_COMPACTION
  CHECK(pthread_mutex_lock(&tx->tree->mutex) == 0);

  if (tx->tree->compacting || tx->tree->done)
    rdb_txn_push(tx, 0, kp, length, value, size);

  CHECK(pthread_mutex_unlock(&tx->tree->mutex) == 0);
#endif

  return RDB_OK;
}

int
rdb_txn_del(rdb_txn_t *tx, const unsigned char *key, size_t length) {
  uint8_t kp[RDB_TREE_DEPTH];
  size_t kn = sizeof(kp);
  int rc;

  if (length == 0 || length > RDB_KEY_SIZE)
    return RDB_EINVAL;

  rdb_convert(kp, key, length);

  rc = rdb_tree_del(tx->tree, &tx->root, kp, kn);

  if (rc != RDB_OK)
    return rc;

#ifdef RDB_BACKGROUND_COMPACTION
  CHECK(pthread_mutex_lock(&tx->tree->mutex) == 0);

  if (tx->tree->compacting || tx->tree->done)
    rdb_txn_push(tx, 1, kp, length, NULL, 0);

  CHECK(pthread_mutex_unlock(&tx->tree->mutex) == 0);
#endif

  return RDB_OK;
}

int
rdb_txn_commit(rdb_txn_t *tx) {
  rdb_t *tree = tx->tree;
#ifdef RDB_BACKGROUND_COMPACTION
  int done = 0;
#endif
  int rc;

  if (!(tree->flags & RDB_RDWR))
    return RDB_EINVAL;

#ifdef RDB_BACKGROUND_COMPACTION
  CHECK(pthread_mutex_lock(&tree->mutex) == 0);

  if (tree->compacting) {
    if (rdb_memusage() < RDB_COMPACT_MAXMEM) {
      CHECK(pthread_mutex_unlock(&tree->mutex) == 0);
      return RDB_OK;
    }

    CHECK(pthread_cond_wait(&tree->master, &tree->mutex) == 0);
    CHECK(tree->compacting == 0);
    CHECK(tree->done == 1);
  }

  done = tree->done;

  tree->done = 0;

  CHECK(pthread_mutex_unlock(&tree->mutex) == 0);

  if (done) {
    if ((rc = rdb_tree_reopen(tree)))
      return rc;

    if ((rc = rdb_txn_merge(tx)))
      return rc;
  }
#endif

  rc = rdb_tree_commit(tree, &tx->root);

  if (rc != RDB_OK)
    return rc;

#ifdef RDB_BACKGROUND_COMPACTION
  if (rdb_needs_compact(tree)) {
    CHECK(pthread_mutex_lock(&tree->mutex) == 0);
    CHECK(tree->compacting == 0);

    tree->snapshot = rdb_snapshot(tree);
    tree->compacting = 1;

    CHECK(pthread_cond_signal(&tree->worker) == 0);
    CHECK(pthread_mutex_unlock(&tree->mutex) == 0);
  }
#else
  if (rdb_needs_compact(tree))
    rc = rdb_tree_compact(tree);
#endif

  return rc;
}

#ifdef RDB_BACKGROUND_COMPACTION
static void *
compact_thread(void *arg) {
  rdb_t *tree = arg;
  rdb_node_t *root;
  int done = 0;

  for (;;) {
    CHECK(pthread_mutex_lock(&tree->mutex) == 0);

    if (!tree->stop && done) {
      tree->compacting = 0;
      tree->snapshot = NULL;
      tree->done = 1;
      CHECK(pthread_cond_signal(&tree->master) == 0);
    }

    while (!tree->stop && (!tree->compacting || tree->done))
      CHECK(pthread_cond_wait(&tree->worker, &tree->mutex) == 0);

    if (tree->stop)
      break;

    root = tree->snapshot;

    tree->snapshot = NULL;

    CHECK(pthread_mutex_unlock(&tree->mutex) == 0);

    CHECK(rdb_tree_dump(tree, root) == RDB_OK);

    done = 1;
  }

  if (tree->snapshot) {
    rdb_node_destroy(tree->snapshot, 0);
    tree->snapshot = NULL;
  }

  if (tree->compacting || tree->done) {
    char file[RDB_PATH_MAX];

    sprintf(file, "%s-compact", tree->path);
    unlink(file);
  }

  tree->compacting = 0;
  tree->done = 0;
  tree->stop = 0;

  CHECK(pthread_cond_signal(&tree->master) == 0);
  CHECK(pthread_mutex_unlock(&tree->mutex) == 0);

  return NULL;
}
#endif /* RDB_BACKGROUND_COMPACTION */

/*
 * Stack
 */

typedef struct rdb_state_s {
  rdb_node_t *node;
  int parent;
  int child;
} rdb_state_t;

typedef struct rdb_stack_s {
  rdb_state_t **items;
  size_t alloc;
  size_t length;
} rdb_stack_t;

static void
rdb_stack_init(rdb_stack_t *z) {
  z->items = NULL;
  z->alloc = 0;
  z->length = 0;
}

static void
rdb_stack_reset(rdb_stack_t *z) {
  size_t i;

  for (i = 0; i < z->length; i++) {
    rdb_state_t *state = z->items[i];
    rdb_node_t *node = state->node;

    if (node->flags & RDB_FLAG_RESOLVED)
      rdb_node_destroy(node, 1);

    rdb_free(state, sizeof(*state));
  }

  z->length = 0;
}

static void
rdb_stack_clear(rdb_stack_t *z) {
  rdb_stack_reset(z);

  if (z->alloc > 0)
    rdb_free(z->items, z->alloc * sizeof(rdb_state_t *));

  z->items = NULL;
  z->alloc = 0;
  z->length = 0;
}

static void
rdb_stack_grow(rdb_stack_t *z, size_t zn) {
  if (zn > z->alloc) {
    z->items = rdb_realloc(z->items,
                           z->alloc * sizeof(rdb_state_t *),
                           zn * sizeof(rdb_state_t *));
    z->alloc = zn;
  }
}

static void
rdb_stack_push(rdb_stack_t *z, const rdb_state_t *x) {
  if (z->length == z->alloc)
    rdb_stack_grow(z, (z->alloc * 3) / 2 + (z->alloc <= 1));

  z->items[z->length++] = (rdb_state_t *)x;
}

static rdb_state_t *
rdb_stack_pop(rdb_stack_t *z) {
  CHECK(z->length > 0);
  return z->items[--z->length];
}

static rdb_state_t *
rdb_stack_top(const rdb_stack_t *z) {
  CHECK(z->length > 0);
  return (rdb_state_t *)z->items[z->length - 1];
}

static void
rdb_stack_add(rdb_stack_t *z, int parent, rdb_node_t *node, int child) {
  rdb_state_t *x = rdb_malloc(sizeof(rdb_state_t));

  x->parent = parent;
  x->node = node;
  x->child = child;

  rdb_stack_push(z, x);
}

static void
rdb_stack_drop(rdb_stack_t *z) {
  rdb_state_t *state = rdb_stack_pop(z);
  rdb_node_t *node = state->node;

  if (node->flags & RDB_FLAG_RESOLVED)
    rdb_node_destroy(node, 1);

  rdb_free(state, sizeof(*state));
}

/*
 * Iterator
 */

struct rdb_iter_s {
  rdb_t *tree;
  rdb_txn_t *tx;
  rdb_node_t *root;
  rdb_stack_t stack;
  int found;
  uint8_t key[RDB_KEY_SIZE];
#ifndef RDB_MMAP
  uint8_t value[RDB_VALUE_SIZE];
#endif
};

rdb_iter_t *
rdb_iter_create(rdb_txn_t *tx) {
  rdb_iter_t *iter = rdb_malloc(sizeof(rdb_iter_t));

  iter->tree = tx->tree;
  iter->tx = tx;
  iter->root = tx->root;
  iter->found = 0;

  rdb_stack_init(&iter->stack);

  return iter;
}

void
rdb_iter_destroy(rdb_iter_t *iter) {
  rdb_stack_clear(&iter->stack);
  rdb_free(iter, sizeof(*iter));
}

int
rdb_iter_first(rdb_iter_t *iter) {
  rdb_node_t *node = iter->root;
  int index = -1;

  rdb_stack_reset(&iter->stack);

  iter->found = 0;

  for (;;) {
    switch (node->type) {
      case RDB_NODE_NULL: {
        return RDB_ENOTFOUND;
      }

      case RDB_NODE_INTERNAL: {
        rdb_internal_t *ni = INTERNAL(node);
        int i;

        for (i = 0; i < 16; i++) {
          rdb_node_t *child = ni->buckets[i];

          if (child->type == RDB_NODE_NULL)
            continue;

          rdb_stack_add(&iter->stack, index, node, i);

          index = i;
          node = child;

          break;
        }

        break;
      }

      case RDB_NODE_LEAF: {
        rdb_stack_add(&iter->stack, index, node, -1);
        iter->found = 1;
        return RDB_OK;
      }

      case RDB_NODE_PTR: {
        node = rdb_resolve(iter->tree, node);

        if (node == NULL)
          return RDB_ECORRUPTION;

        node->flags |= RDB_FLAG_RESOLVED;

        break;
      }

      default: {
        return RDB_ECORRUPTION;
      }
    }
  }
}

int
rdb_iter_seek(rdb_iter_t *iter, const unsigned char *key, size_t length) {
  rdb_node_t *node = iter->root;
  uint8_t tmp[RDB_TREE_DEPTH];
  size_t kn = sizeof(tmp);
  uint8_t *kp = tmp;
  int index = -1;

  if (length == 0 || length > RDB_KEY_SIZE)
    return RDB_EINVAL;

  rdb_convert(kp, key, length);

  rdb_stack_reset(&iter->stack);

  iter->found = 0;

  for (;;) {
    switch (node->type) {
      case RDB_NODE_NULL: {
        rdb_stack_add(&iter->stack, index, node, -1);
        return rdb_iter_next(iter);
      }

      case RDB_NODE_INTERNAL: {
        rdb_internal_t *ni = INTERNAL(node);
        int cmp = rdb_node_compare(node, kp, kn);

        if (cmp < 0) {
          if (node->flags & RDB_FLAG_RESOLVED)
            rdb_node_destroy(node, 1);

          return RDB_ENOTFOUND;
        }

        if (cmp > 0) {
          rdb_stack_add(&iter->stack, index, node, -1);
          return rdb_iter_next(iter);
        }

        kp += node->length;
        kn -= node->length;

        rdb_stack_add(&iter->stack, index, node, kp[0]);

        index = kp[0];
        node = ni->buckets[index];

        kp += 1;
        kn -= 1;

        break;
      }

      case RDB_NODE_LEAF: {
        rdb_stack_add(&iter->stack, index, node, -1);
        iter->found = 1;
        return RDB_OK;
      }

      case RDB_NODE_PTR: {
        node = rdb_resolve(iter->tree, node);

        if (node == NULL)
          return RDB_ECORRUPTION;

        node->flags |= RDB_FLAG_RESOLVED;

        break;
      }

      default: {
        return RDB_ECORRUPTION;
      }
    }
  }
}

int
rdb_iter_next(rdb_iter_t *iter) {
  if (iter->found) {
    rdb_stack_drop(&iter->stack);
    iter->found = 0;
  }

  while (iter->stack.length > 0) {
    rdb_state_t *state = rdb_stack_top(&iter->stack);
    rdb_node_t *node = state->node;

    switch (node->type) {
      case RDB_NODE_NULL: {
        rdb_stack_drop(&iter->stack);
        break;
      }

      case RDB_NODE_INTERNAL: {
        const rdb_internal_t *ni = INTERNAL(node);

        if (state->child == 15) {
          rdb_stack_drop(&iter->stack);
          break;
        }

        node = ni->buckets[++state->child];

        rdb_stack_add(&iter->stack, state->child, node, -1);

        break;
      }

      case RDB_NODE_LEAF: {
        iter->found = 1;
        return RDB_OK;
      }

      case RDB_NODE_PTR: {
        node = rdb_resolve(iter->tree, node);

        if (node == NULL)
          return RDB_ECORRUPTION;

        node->flags |= RDB_FLAG_RESOLVED;

        state->node = node;

        break;
      }

      default: {
        return RDB_ECORRUPTION;
      }
    }
  }

  return RDB_ENOTFOUND;
}

int
rdb_iter_key(rdb_iter_t *iter, const unsigned char **key, size_t *length) {
  uint8_t kp[RDB_TREE_DEPTH];
  size_t kn = 0;
  size_t i;

  for (i = 0; i < iter->stack.length; i++) {
    rdb_state_t *state = iter->stack.items[i];
    rdb_node_t *node = state->node;

    if (kn + (state->parent != -1) + node->length > RDB_TREE_DEPTH)
      return RDB_EINVAL;

    if (state->parent != -1)
      kp[kn++] = state->parent;

    memcpy(kp + kn, node->prefix, node->length);

    kn += node->length;
  }

  if (kn != RDB_TREE_DEPTH)
    return RDB_EINVAL;

  rdb_nibs_write(iter->key, kp, kn);

  *key = iter->key;
  *length = kn / 2;

  return RDB_OK;
}

int
rdb_iter_value(rdb_iter_t *iter, const unsigned char **value, size_t *size) {
  rdb_node_t *node;

  if (iter->stack.length == 0)
    return RDB_EINVAL;

  node = rdb_stack_top(&iter->stack)->node;

  if (node->type != RDB_NODE_LEAF)
    return RDB_EINVAL;

#ifdef RDB_MMAP
  if (!rdb_retrieve(iter->tree, node, value, size))
    return RDB_ECORRUPTION;

  return RDB_OK;
#else
  if (!rdb_retrieve(iter->tree, node, iter->value, size))
    return RDB_ECORRUPTION;

  *value = iter->value;

  return RDB_OK;
#endif
}

/*
 * Helpers
 */

const char *
rdb_strerror(int code) {
  switch (code) {
#define X(c) case (c): return #c
    X(RDB_OK);
    X(RDB_EINVAL);
    X(RDB_ENOTFOUND);
    X(RDB_ECORRUPTION);
    X(RDB_ENOUPDATE);
    X(RDB_EBADWRITE);
    X(RDB_EBADOPEN);
    X(RDB_EBADCLOSE);
#undef X
  }
  return "RDB_UNKNOWN";
}

size_t
rdb_memusage(void) {
  size_t usage;
  RDB_USAGE_LOCK;
  usage = rdb_usage;
  RDB_USAGE_UNLOCK;
  return usage;
}
