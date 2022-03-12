/*!
 * dbformat.h - db format for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LDB_DBFORMAT_H
#define LDB_DBFORMAT_H

#include <stddef.h>
#include <stdint.h>

#include "util/types.h"

/*
 * Constants
 */

/* Grouping of constants. We may want to make some of these
   parameters set via options. */
#define LDB_NUM_LEVELS 7 /* kNumLevels */

/* Level-0 compaction is started when we hit this many files. */
#define LDB_L0_COMPACTION_TRIGGER 4 /* kL0_CompactionTrigger */

/* Soft limit on number of level-0 files. We slow down writes at this point. */
#define LDB_L0_SLOWDOWN_WRITES_TRIGGER 8 /* kL0_SlowdownWritesTrigger */

/* Maximum number of level-0 files. We stop writes at this point. */
#define LDB_L0_STOP_WRITES_TRIGGER 12 /* kL0_StopWritesTrigger */

/* Maximum level to which a new compacted memtable is pushed if it
   does not create overlap. We try to push to level 2 to avoid the
   relatively expensive level 0=>1 compactions and to avoid some
   expensive manifest file operations. We do not push all the way to
   the largest level since that can generate a lot of wasted disk
   space if the same key space is being repeatedly overwritten. */
#define LDB_MAX_MEM_COMPACT_LEVEL 2 /* kMaxMemCompactLevel */

/* Approximate gap in bytes between samples of data read during iteration. */
#define LDB_READ_BYTES_PERIOD 1048576 /* kReadBytesPeriod */

/* Value types encoded as the last component of internal keys.
   DO NOT CHANGE THESE ENUM VALUES: they are embedded in the on-disk
   data structures. */
enum ldb_valtype {
  LDB_TYPE_DELETION = 0x0, /* kTypeDeletion */
  LDB_TYPE_VALUE = 0x1 /* kTypeValue */
};

/* LDB_VALTYPE_SEEK defines the ldb_valtype that should be passed when
 * constructing a ldb_pkey_t object for seeking to a particular
 * sequence number (since we sort sequence numbers in decreasing order
 * and the value type is embedded as the low 8 bits in the sequence
 * number in internal keys, we need to use the highest-numbered
 * ldb_valtype, not the lowest).
 */
#define LDB_VALTYPE_SEEK LDB_TYPE_VALUE /* kValueTypeForSeek */

/* We leave eight bits empty at the bottom so a type and sequence#
   can be packed together into 64-bits. */
#define LDB_MAX_SEQUENCE ((UINT64_C(1) << 56) - 1) /* kMaxSequenceNumber */

/*
 * Types
 */

struct ldb_bloom_s;
struct ldb_comparator_s;

typedef enum ldb_valtype ldb_valtype_t;

typedef uint64_t ldb_seqnum_t;

/* ParsedInternalKey */
typedef struct ldb_pkey_s {
  ldb_slice_t user_key;
  ldb_seqnum_t sequence;
  ldb_valtype_t type;
} ldb_pkey_t;

/* InternalKey */
typedef ldb_buffer_t ldb_ikey_t;

/* LookupKey */
typedef struct ldb_lkey_s {
  /* We construct a char array of the form:
   *
   *    klength  varint32               <-- start
   *    userkey  char[klength]          <-- kstart
   *    tag      uint64
   *                                    <-- end
   *
   * The array is a suitable MemTable key.
   * The suffix starting with "userkey" can be used as an ldb_ikey_t.
   */
  const uint8_t *start;
  const uint8_t *kstart;
  const uint8_t *end;
  uint8_t space[200]; /* Avoid allocation for short keys. */
} ldb_lkey_t;

/*
 * Helpers
 */

ldb_slice_t
ldb_extract_user_key(const ldb_slice_t *key);

/*
 * ParsedInternalKey
 */

void
ldb_pkey_init(ldb_pkey_t *key,
              const ldb_slice_t *user_key,
              ldb_seqnum_t sequence,
              ldb_valtype_t type);

/* InternalKeyEncodingLength */
size_t
ldb_pkey_size(const ldb_pkey_t *x);

/* AppendInternalKey */
void
ldb_pkey_export(ldb_buffer_t *z, const ldb_pkey_t *x);

/* ParseInternalKey */
int
ldb_pkey_import(ldb_pkey_t *z, const ldb_slice_t *x);

void
ldb_pkey_debug(ldb_buffer_t *z, const ldb_pkey_t *x);

/*
 * InternalKey
 */

void
ldb_ikey_init(ldb_ikey_t *ikey);

void
ldb_ikey_set(ldb_ikey_t *ikey,
             const ldb_slice_t *user_key,
             ldb_seqnum_t sequence,
             ldb_valtype_t type);

void
ldb_ikey_clear(ldb_ikey_t *ikey);

void
ldb_ikey_copy(ldb_ikey_t *z, const ldb_ikey_t *x);

ldb_slice_t
ldb_ikey_user_key(const ldb_ikey_t *ikey);

/* PutLengthPrefixedSlice */
void
ldb_ikey_export(ldb_ikey_t *z, const ldb_ikey_t *x);

void
ldb_ikey_debug(ldb_buffer_t *z, const ldb_ikey_t *x);

/*
 * LookupKey
 */

void
ldb_lkey_init(ldb_lkey_t *lkey,
              const ldb_slice_t *user_key,
              ldb_seqnum_t sequence);

void
ldb_lkey_clear(ldb_lkey_t *lkey);

/* Return a key suitable for lookup in a MemTable. */
ldb_slice_t
ldb_lkey_memtable_key(const ldb_lkey_t *lkey);

/* Return an internal key (suitable for passing to an internal iterator) */
ldb_slice_t
ldb_lkey_internal_key(const ldb_lkey_t *lkey);

/* Return the user key */
ldb_slice_t
ldb_lkey_user_key(const ldb_lkey_t *lkey);

/*
 * InternalKeyComparator
 */

void
ldb_ikc_init(struct ldb_comparator_s *ikc,
             const struct ldb_comparator_s *user_comparator);

/*
 * InternalFilterPolicy
 */

void
ldb_ifp_init(struct ldb_bloom_s *ifp, const struct ldb_bloom_s *user_policy);

#endif /* LDB_DBFORMAT_H */
