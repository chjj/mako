#include <string.h>
#include <torsion/util.h>
#include "khash.h"

#define kh_hash_hash_func(x) murmur3_sum(x, 32, 0xfba4c795)
#define kh_hash_hash_equal(x, y) (memcmp(x, y, 32) == 0)

#define KHASH_SET_INIT_HASH(name)                                \
  KHASH_INIT(name, unsigned char *, char, 0, kh_hash_hash_func,  \
                                             kh_hash_hash_equal)

#define KHASH_MAP_INIT_HASH(name, khval_t)                          \
  KHASH_INIT(name, unsigned char *, khval_t, 1, kh_hash_hash_func,  \
                                                kh_hash_hash_equal)

#define KHASH_SET_INIT_CONST_HASH(name)                                \
  KHASH_INIT(name, const unsigned char *, char, 0, kh_hash_hash_func,  \
                                                   kh_hash_hash_equal)

#define KHASH_MAP_INIT_CONST_HASH(name, khval_t)                          \
  KHASH_INIT(name, const unsigned char *, khval_t, 1, kh_hash_hash_func,  \
                                                      kh_hash_hash_equal)

#define KHASH_SET_INIT_OUTPOINT(name)                           \
  KHASH_INIT(name, fp_outpoint_t *, char, 0, fp_outpoint_hash,  \
                                             fp_outpoint_equal)

#define KHASH_MAP_INIT_OUTPOINT(name, khval_t)                     \
  KHASH_INIT(name, fp_outpoint_t *, khval_t, 1, fp_outpoint_hash,  \
                                                fp_outpoint_equal)

#define KHASH_SET_INIT_CONST_OUTPOINT(name)                           \
  KHASH_INIT(name, const fp_outpoint_t *, char, 0, fp_outpoint_hash,  \
                                                   fp_outpoint_equal)

#define KHASH_MAP_INIT_CONST_OUTPOINT(name, khval_t)                     \
  KHASH_INIT(name, const fp_outpoint_t *, khval_t, 1, fp_outpoint_hash,  \
                                                      fp_outpoint_equal)
