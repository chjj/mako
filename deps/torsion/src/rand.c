/*!
 * rand.c - RNG for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 */

/**
 * Random Number Generation
 *
 * We use a ChaCha20 RNG with a design inspired by
 * libsodium[1]. Our primary difference is a much
 * more complicated seeding procedure which ensures
 * strong randomness (similar to Bitcoin Core[2]).
 *
 * The seeding procedure uses a combination of OS
 * entropy, hardware entropy, and entropy manually
 * gathered from the environment. See entropy/ for
 * more information.
 *
 * We expose a global fork-aware and thread-safe
 * RNG. We use thread local storage for the global
 * context. This avoids us having to link to
 * pthread and deal with other OS compat issues.
 *
 * The RNG below is not used anywhere internally,
 * and as such, libtorsion can build without it (in
 * the case that more portability is desired).
 *
 * [1] https://github.com/jedisct1/libsodium/blob/master/src/libsodium
 *     /randombytes/internal/randombytes_internal_random.c
 * [2] https://github.com/bitcoin/bitcoin/blob/master/src/random.cpp
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <torsion/hash.h>
#include <torsion/rand.h>
#include <torsion/stream.h>
#include <torsion/util.h>
#include "entropy/entropy.h"
#include "internal.h"

/*
 * RNG
 */

typedef struct rng_s {
  uint32_t key[8];
  uint64_t nonce;
  uint32_t pool[128];
  size_t pos;
  int rdrand;
  int started;
  long pid;
} rng_t;

static int
rng_init(rng_t *rng) {
  unsigned char *key = (unsigned char *)rng->key;
  unsigned char seed[64];
  sha256_t hash;

  memset(rng, 0, sizeof(*rng));

  sha256_init(&hash);

  /* LCOV_EXCL_START */
  if (!torsion_has_sysrand()) {
    if (!torsion_hwrand(seed, 64))
      return 0;

    sha256_update(&hash, seed, 64);
  } else {
    if (!torsion_sysrand(seed, 64))
      return 0;

    sha256_update(&hash, seed, 64);

    if (torsion_hwrand(seed, 64))
      sha256_update(&hash, seed, 64);
  }
  /* LCOV_EXCL_STOP */

  sha256_final(&hash, key);

  rng->rdrand = torsion_has_rdrand();

  torsion_memzero(seed, sizeof(seed));
  torsion_memzero(&hash, sizeof(hash));

  return 1;
}

static void
rng_crypt(const rng_t *rng, void *data, size_t size) {
  chacha20_t ctx;

  chacha20_init(&ctx, (const unsigned char *)rng->key, 32,
                      (const unsigned char *)&rng->nonce, 8,
                      0);

  chacha20_crypt(&ctx, (unsigned char *)data,
                       (const unsigned char *)data,
                       size);

  torsion_memzero(&ctx, sizeof(ctx));
}

static void
rng_read(const rng_t *rng, void *dst, size_t size) {
  if (size > 0)
    memset(dst, 0, size);

  rng_crypt(rng, dst, size);
}

static void
rng_generate(rng_t *rng, void *dst, size_t size) {
  /* Read the keystream. */
  rng_read(rng, dst, size);

  /* Mix in some user entropy. */
  rng->key[0] ^= (uint32_t)size;

  /* Mix in some hardware entropy. We sacrifice
     only 32 bits here, lest RDRAND is backdoored.
     See: https://pastebin.com/A07q3nL3 */
  if (rng->rdrand)
    rng->key[7] ^= torsion_rdrand32();

  /* Re-key immediately. */
  rng->nonce++;

  /* At this point, the CTR-DRBG simply reads the
     keystream again in order to rekey. We mimic
     libsodium instead by XOR'ing the partially
     modified key with its own keystream. In truth,
     there's probably not really a difference in
     terms of security, as the outputs in both
     scenarios are dependent on the key. */
  rng_crypt(rng, rng->key, 32);
}

static uint32_t
rng_random(rng_t *rng) {
  uint32_t x;
  size_t i;

  if (rng->pos == 0) {
    /* Read the keystream. */
    rng_read(rng, rng->pool, 512);

    /* Mix in some hardware entropy. */
    if (rng->rdrand)
      rng->key[7] ^= torsion_rdrand32();

    /* Re-key every 512 bytes. */
    for (i = 0; i < 8; i++)
      rng->key[i] ^= rng->pool[120 + i];

    for (i = 0; i < 8; i++)
      rng->pool[120 + i] = 0;

    rng->nonce++;
    rng->pos = 120;
  }

  x = rng->pool[--rng->pos];

  rng->pool[rng->pos] = 0;

  return x;
}

static uint32_t
rng_uniform(rng_t *rng, uint32_t max) {
  /* See: http://www.pcg-random.org/posts/bounded-rands.html */
  uint32_t x, r;

  if (max <= 1)
    return 0;

  do {
    x = rng_random(rng);
    r = x % max;
  } while (x - r > (-max));

  return r;
}

/*
 * Global Lock
 */

#if defined(__MINGW32__) && defined(_WIN32)
/* MinGW autolinks to libwinpthread when TLS
 * is used. This means our library will not be
 * redistributable on Windows unless we ship
 * libwinpthread.dll as well.
 *
 * To avoid this, we utilize the win32 API
 * directly and use a global lock instead.
 */

#undef TORSION_TLS

#include <windows.h>

static CRITICAL_SECTION rng_lock;

static void
rng_global_lock(void) {
  static int initialized = 0;
  static HANDLE event = NULL;
  HANDLE created, existing;

  if (initialized == 0) {
    created = CreateEvent(NULL, 1, 0, NULL);

    if (created == NULL)
      torsion_abort(); /* LCOV_EXCL_LINE */

    existing = InterlockedCompareExchangePointer(&event, created, NULL);

    if (existing == NULL) {
      InitializeCriticalSection(&rng_lock);

      if (!SetEvent(created))
        torsion_abort(); /* LCOV_EXCL_LINE */

      initialized = 1;
    } else {
      CloseHandle(created);

      if (WaitForSingleObject(existing, INFINITE) != WAIT_OBJECT_0)
        torsion_abort(); /* LCOV_EXCL_LINE */
    }
  }

  EnterCriticalSection(&rng_lock);
}

static void
rng_global_unlock(void) {
  LeaveCriticalSection(&rng_lock);
}

#else /* !__MINGW32__ */

#if !defined(TORSION_TLS) && defined(TORSION_HAVE_PTHREAD)
#  define TORSION_USE_PTHREAD
#endif

#ifdef TORSION_USE_PTHREAD
#  include <pthread.h>
static pthread_mutex_t rng_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

static void
rng_global_lock(void) {
#ifdef TORSION_USE_PTHREAD
  if (pthread_mutex_lock(&rng_lock) != 0)
    torsion_abort(); /* LCOV_EXCL_LINE */
#endif
}

static void
rng_global_unlock(void) {
#ifdef TORSION_USE_PTHREAD
  if (pthread_mutex_unlock(&rng_lock) != 0)
    torsion_abort(); /* LCOV_EXCL_LINE */
#endif
}

#endif /* !__MINGW32__ */

/*
 * Global Context
 */

#if defined(TORSION_TLS)
static TORSION_TLS rng_t rng_state;
#else
static rng_t rng_state;
#endif

static int
rng_global_init(void) {
  long pid = torsion_getpid();

  if (!rng_state.started || rng_state.pid != pid) {
    if (!rng_init(&rng_state))
      return 0; /* LCOV_EXCL_LINE */

    rng_state.started = 1;
    rng_state.pid = pid;
  }

  return 1;
}

/*
 * Random
 */

int
torsion_getentropy(void *dst, size_t size) {
  if (!torsion_has_sysrand())
    return torsion_hwrand(dst, size);
  return torsion_sysrand(dst, size);
}

int
torsion_getrandom(void *dst, size_t size) {
  rng_global_lock();

  /* LCOV_EXCL_START */
  if (!rng_global_init()) {
    if (size > 0)
      memset(dst, 0, size);

    rng_global_unlock();

    return 0;
  }
  /* LCOV_EXCL_STOP */

  rng_generate(&rng_state, dst, size);
  rng_global_unlock();

  return 1;
}

int
torsion_random(uint32_t *num) {
  rng_global_lock();

  /* LCOV_EXCL_START */
  if (!rng_global_init()) {
    *num = 0;
    rng_global_unlock();
    return 0;
  }
  /* LCOV_EXCL_STOP */

  *num = rng_random(&rng_state);

  rng_global_unlock();

  return 1;
}

int
torsion_uniform(uint32_t *num, uint32_t max) {
  rng_global_lock();

  /* LCOV_EXCL_START */
  if (!rng_global_init()) {
    *num = 0;
    rng_global_unlock();
    return 0;
  }
  /* LCOV_EXCL_STOP */

  *num = rng_uniform(&rng_state, max);

  rng_global_unlock();

  return 1;
}
