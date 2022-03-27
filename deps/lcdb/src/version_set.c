/*!
 * version_set.c - version set for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "table/iterator.h"
#include "table/merger.h"
#include "table/table.h"
#include "table/two_level_iterator.h"

#include "util/buffer.h"
#include "util/coding.h"
#include "util/comparator.h"
#include "util/env.h"
#include "util/internal.h"
#include "util/options.h"
#include "util/port.h"
#include "util/rbt.h"
#include "util/slice.h"
#include "util/status.h"
#include "util/strutil.h"
#include "util/vector.h"

#include "dbformat.h"
#include "filename.h"
#include "log_format.h"
#include "log_reader.h"
#include "log_writer.h"
#include "table_cache.h"
#include "version_edit.h"
#include "version_set.h"

/*
 * Helpers
 */

static size_t
target_file_size(const ldb_dbopt_t *options) {
  return options->max_file_size;
}

/* Maximum bytes of overlaps in grandparent (i.e., level+2) before we
   stop building a single file in a level->level+1 compaction. */
static int64_t
max_grandparent_overlap_bytes(const ldb_dbopt_t *options) {
  return 10 * target_file_size(options);
}

/* Maximum number of bytes in all compacted files. We avoid expanding
   the lower level file set of a compaction if it would make the
   total compaction cover more than this many bytes. */
static int64_t
expanded_compaction_byte_size_limit(const ldb_dbopt_t *options) {
  return 25 * target_file_size(options);
}

static double
max_bytes_for_level(const ldb_dbopt_t *options, int level) {
  /* Note: the result for level zero is not really used since we set
     the level-0 compaction threshold based on number of files. */
  double result = 10. * 1048576.0;

  (void)options;

  /* Result for both level-0 and level-1. */
  while (level > 1) {
    result *= 10;
    level--;
  }

  return result;
}

static uint64_t
max_file_size_for_level(const ldb_dbopt_t *options, int level) {
  /* We could vary per level to reduce number of files? */
  (void)level;
  return target_file_size(options);
}

static int64_t
total_file_size(const ldb_vector_t *files) {
  int64_t sum = 0;
  size_t i;

  for (i = 0; i < files->length; i++) {
    const ldb_filemeta_t *f = files->items[i];

    sum += f->file_size;
  }

  return sum;
}

int
find_file(const ldb_comparator_t *icmp,
          const ldb_vector_t *files,
          const ldb_slice_t *key) {
  uint32_t left = 0;
  uint32_t right = files->length;

  while (left < right) {
    uint32_t mid = (left + right) / 2;
    const ldb_filemeta_t *f = files->items[mid];

    if (ldb_compare(icmp, &f->largest, key) < 0) {
      /* Key at "mid.largest" is < "target". Therefore all
         files at or before "mid" are uninteresting. */
      left = mid + 1;
    } else {
      /* Key at "mid.largest" is >= "target". Therefore all files
         after "mid" are uninteresting. */
      right = mid;
    }
  }

  return right;
}

static int
after_file(const ldb_comparator_t *ucmp,
           const ldb_slice_t *user_key,
           const ldb_filemeta_t *f) {
  ldb_slice_t largest;

  /* Null user_key occurs before all keys
     and is therefore never after *f. */
  if (user_key == NULL)
    return 0;

  largest = ldb_ikey_user_key(&f->largest);

  return ldb_compare(ucmp, user_key, &largest) > 0;
}

static int
before_file(const ldb_comparator_t *ucmp,
            const ldb_slice_t *user_key,
            const ldb_filemeta_t *f) {
  ldb_slice_t smallest;

  /* Null user_key occurs after all keys
     and is therefore never before *f. */
  if (user_key == NULL)
    return 0;

  smallest = ldb_ikey_user_key(&f->smallest);

  return ldb_compare(ucmp, user_key, &smallest) < 0;
}

int
some_file_overlaps_range(const ldb_comparator_t *icmp,
                         int disjoint_sorted_files,
                         const ldb_vector_t *files,
                         const ldb_slice_t *smallest_user_key,
                         const ldb_slice_t *largest_user_key) {
  const ldb_comparator_t *ucmp = icmp->user_comparator;
  uint32_t index = 0;

  if (!disjoint_sorted_files) {
    /* Need to check against all files. */
    size_t i;

    for (i = 0; i < files->length; i++) {
      const ldb_filemeta_t *f = files->items[i];

      if (after_file(ucmp, smallest_user_key, f) ||
          before_file(ucmp, largest_user_key, f)) {
        /* No overlap. */
      } else {
        return 1; /* Overlap. */
      }
    }

    return 0;
  }

  /* Binary search over file list. */
  if (smallest_user_key != NULL) {
    /* Find the earliest possible internal key for smallest_user_key. */
    ldb_ikey_t small_key;

    ldb_ikey_init(&small_key);

    ldb_ikey_set(&small_key, smallest_user_key, LDB_MAX_SEQUENCE,
                                                LDB_VALTYPE_SEEK);

    index = find_file(icmp, files, &small_key);

    ldb_ikey_clear(&small_key);
  }

  if (index >= files->length) {
    /* Beginning of range is after all files, so no overlap. */
    return 0;
  }

  return !before_file(ucmp, largest_user_key, files->items[index]);
}

/*
 * Version::LevelFileNumIterator
 */

/* An internal iterator. For a given version/level pair, yields
   information about the files in the level. For a given entry, key()
   is the largest key that occurs in the file, and value() is an
   16-byte value containing the file number and file size, both
   encoded using ldb_fixed64_write. */
typedef struct ldb_numiter_s {
  ldb_comparator_t icmp;
  const ldb_vector_t *flist; /* ldb_filemeta_t */
  uint32_t index;
  uint8_t value[16];
} ldb_numiter_t;

static void
ldb_numiter_init(ldb_numiter_t *iter,
                 const ldb_comparator_t *icmp,
                 const ldb_vector_t *flist) {
  iter->icmp = *icmp;
  iter->flist = flist;
  iter->index = flist->length; /* Mark as invalid. */
}

static void
ldb_numiter_clear(ldb_numiter_t *iter) {
  (void)iter;
}

static int
ldb_numiter_valid(const ldb_numiter_t *iter) {
  return iter->index < iter->flist->length;
}

static void
ldb_numiter_seek(ldb_numiter_t *iter, const ldb_slice_t *target) {
  iter->index = find_file(&iter->icmp, iter->flist, target);
}

static void
ldb_numiter_first(ldb_numiter_t *iter) {
  iter->index = 0;
}

static void
ldb_numiter_last(ldb_numiter_t *iter) {
  iter->index = iter->flist->length == 0 ? 0 : iter->flist->length - 1;
}

static void
ldb_numiter_next(ldb_numiter_t *iter) {
  assert(ldb_numiter_valid(iter));
  iter->index++;
}

static void
ldb_numiter_prev(ldb_numiter_t *iter) {
  assert(ldb_numiter_valid(iter));

  if (iter->index == 0)
    iter->index = iter->flist->length; /* Marks as invalid. */
  else
    iter->index--;
}

static ldb_slice_t
ldb_numiter_key(const ldb_numiter_t *iter) {
  const ldb_filemeta_t *file;

  assert(ldb_numiter_valid(iter));

  file = iter->flist->items[iter->index];

  return file->largest;
}

static ldb_slice_t
ldb_numiter_value(const ldb_numiter_t *iter) {
  uint8_t *value = (uint8_t *)iter->value;
  const ldb_filemeta_t *file;

  assert(ldb_numiter_valid(iter));

  file = iter->flist->items[iter->index];

  ldb_fixed64_write(value + 0, file->number);
  ldb_fixed64_write(value + 8, file->file_size);

  return ldb_slice(value, sizeof(iter->value));
}

static int
ldb_numiter_status(const ldb_numiter_t *iter) {
  (void)iter;
  return LDB_OK;
}

LDB_ITERATOR_FUNCTIONS(ldb_numiter);

static ldb_iter_t *
ldb_numiter_create(const ldb_comparator_t *icmp, const ldb_vector_t *flist) {
  ldb_numiter_t *iter = ldb_malloc(sizeof(ldb_numiter_t));

  ldb_numiter_init(iter, icmp, flist);

  return ldb_iter_create(iter, &ldb_numiter_table);
}

static ldb_iter_t *
get_file_iterator(void *arg,
                  const ldb_readopt_t *options,
                  const ldb_slice_t *file_value) {
  ldb_tcache_t *cache = (ldb_tcache_t *)arg;

  if (file_value->size != 16) {
    /* "FileReader invoked with unexpected value" */
    return ldb_emptyiter_create(LDB_CORRUPTION);
  }

  return ldb_tcache_iterate(cache, options,
                            ldb_fixed64_decode(file_value->data + 0),
                            ldb_fixed64_decode(file_value->data + 8),
                            NULL);
}

static ldb_iter_t *
ldb_concatiter_create(const ldb_version_t *ver,
                      const ldb_readopt_t *options,
                      int level) {
  ldb_iter_t *iter = ldb_numiter_create(&ver->vset->icmp, &ver->files[level]);

  return ldb_twoiter_create(iter,
                            &get_file_iterator,
                            ver->vset->table_cache,
                            options);
}

/*
 * Saver (for Version::Get)
 */

typedef struct saver_s {
  enum {
    S_NOTFOUND,
    S_FOUND,
    S_DELETED,
    S_CORRUPT
  } state;
  const ldb_comparator_t *ucmp;
  ldb_slice_t user_key;
  ldb_buffer_t *value;
} saver_t;

static void
save_value(void *arg, const ldb_slice_t *ikey, const ldb_slice_t *v) {
  saver_t *s = (saver_t *)arg;
  ldb_pkey_t pkey;

  if (!ldb_pkey_import(&pkey, ikey)) {
    s->state = S_CORRUPT;
    return;
  }

  if (ldb_compare(s->ucmp, &pkey.user_key, &s->user_key) == 0) {
    s->state = (pkey.type == LDB_TYPE_VALUE) ? S_FOUND : S_DELETED;

    if (s->state == S_FOUND && s->value != NULL)
      ldb_buffer_set(s->value, v->data, v->size);
  }
}

/*
 * GetState (for Version::Get)
 */

typedef struct getstate_s {
  saver_t saver;
  ldb_getstats_t *stats;
  const ldb_readopt_t *options;
  ldb_slice_t ikey;
  ldb_filemeta_t *last_file_read;
  int last_file_read_level;
  ldb_vset_t *vset;
  int status;
  int found;
} getstate_t;

static int
getstate_match(void *arg, int level, ldb_filemeta_t *f) {
  getstate_t *state = (getstate_t *)arg;
  ldb_tcache_t *cache = state->vset->table_cache;

  if (state->stats->seek_file == NULL &&
      state->last_file_read != NULL) {
    /* We have had more than one seek for this read. Charge the 1st file. */
    state->stats->seek_file = state->last_file_read;
    state->stats->seek_file_level = state->last_file_read_level;
  }

  state->last_file_read = f;
  state->last_file_read_level = level;

  state->status = ldb_tcache_get(cache,
                                 state->options,
                                 f->number,
                                 f->file_size,
                                 &state->ikey,
                                 &state->saver,
                                 save_value);

  if (state->status != LDB_OK) {
    state->found = 1;
    return 0;
  }

  switch (state->saver.state) {
    case S_NOTFOUND:
      return 1; /* Keep searching in other files. */
    case S_FOUND:
      state->found = 1;
      return 0;
    case S_DELETED:
      return 0;
    case S_CORRUPT:
      state->status = LDB_CORRUPTION; /* "corrupted key for [saver.user_key]" */
      state->found = 1;
      return 0;
  }

  /* Not reached. Added to avoid false compilation warnings of
     "control reaches end of non-void function". */
  return 0;
}

/*
 * SampleState (for Version::RecordReadSample)
 */

typedef struct samplestate_s {
  ldb_getstats_t stats; /* Holds first matching file. */
  int matches;
} samplestate_t;

static int
samplestate_match(void *arg, int level, ldb_filemeta_t *f) {
  samplestate_t *state = (samplestate_t *)arg;

  state->matches++;

  if (state->matches == 1) {
    /* Remember first match. */
    state->stats.seek_file = f;
    state->stats.seek_file_level = level;
  }

  /* We can stop iterating once we have a second match. */
  return state->matches < 2;
}

/*
 * Version
 */

static void
ldb_version_init(ldb_version_t *ver, ldb_vset_t *vset) {
  int level;

  ver->vset = vset;
  ver->next = ver;
  ver->prev = ver;
  ver->refs = 0;
  ver->file_to_compact = NULL;
  ver->file_to_compact_level = 1;
  ver->compaction_score = 1;
  ver->compaction_level = 1;

  for (level = 0; level < LDB_NUM_LEVELS; level++)
    ldb_vector_init(&ver->files[level]);
}

static void
ldb_version_clear(ldb_version_t *ver) {
  size_t i;
  int level;

  assert(ver->refs == 0);

  /* Remove from linked list. */
  ver->prev->next = ver->next;
  ver->next->prev = ver->prev;

  /* Drop references to files. */
  for (level = 0; level < LDB_NUM_LEVELS; level++) {
    for (i = 0; i < ver->files[level].length; i++) {
      ldb_filemeta_t *f = ver->files[level].items[i];
      ldb_filemeta_unref(f);
    }

    ldb_vector_clear(&ver->files[level]);
  }
}

ldb_version_t *
ldb_version_create(ldb_vset_t *vset) {
  ldb_version_t *ver = ldb_malloc(sizeof(ldb_version_t));
  ldb_version_init(ver, vset);
  return ver;
}

void
ldb_version_destroy(ldb_version_t *ver) {
  ldb_version_clear(ver);
  ldb_free(ver);
}

int
ldb_version_num_files(const ldb_version_t *ver, int level) {
  return ver->files[level].length;
}

void
ldb_version_add_iterators(ldb_version_t *ver,
                          const ldb_readopt_t *options,
                          ldb_vector_t *iters) {
  ldb_tcache_t *table_cache = ver->vset->table_cache;
  int level;
  size_t i;

  /* Merge all level zero files together since they may overlap. */
  for (i = 0; i < ver->files[0].length; i++) {
    ldb_filemeta_t *item = ver->files[0].items[i];
    ldb_iter_t *iter = ldb_tcache_iterate(table_cache,
                                          options,
                                          item->number,
                                          item->file_size,
                                          NULL);

    ldb_vector_push(iters, iter);
  }

  /* For levels > 0, we can use a concatenating iterator that sequentially
     walks through the non-overlapping files in the level, opening them
     lazily. */
  for (level = 1; level < LDB_NUM_LEVELS; level++) {
    if (ver->files[level].length > 0) {
      ldb_iter_t *iter = ldb_concatiter_create(ver, options, level);

      ldb_vector_push(iters, iter);
    }
  }
}

static int
newest_first(void *x, void *y) {
  const ldb_filemeta_t *a = x;
  const ldb_filemeta_t *b = y;

  if (a->number == b->number)
    return 0;

  return a->number < b->number ? 1 : -1;
}

static void
ldb_version_for_each_overlapping(ldb_version_t *ver,
                                 const ldb_slice_t *user_key,
                                 const ldb_slice_t *internal_key,
                                 void *arg,
                                 int (*func)(void *, int, ldb_filemeta_t *)) {
  const ldb_comparator_t *ucmp = ver->vset->icmp.user_comparator;
  ldb_vector_t tmp;
  uint32_t i;
  int level;

  /* Search level-0 in order from newest to oldest. */
  ldb_vector_init(&tmp);
  ldb_vector_grow(&tmp, ver->files[0].length);

  for (i = 0; i < ver->files[0].length; i++) {
    ldb_filemeta_t *f = ver->files[0].items[i];
    ldb_slice_t small_key = ldb_ikey_user_key(&f->smallest);
    ldb_slice_t large_key = ldb_ikey_user_key(&f->largest);

    if (ldb_compare(ucmp, user_key, &small_key) >= 0 &&
        ldb_compare(ucmp, user_key, &large_key) <= 0) {
      ldb_vector_push(&tmp, f);
    }
  }

  if (tmp.length > 0) {
    ldb_vector_sort(&tmp, newest_first);

    for (i = 0; i < tmp.length; i++) {
      if (!func(arg, 0, tmp.items[i])) {
        ldb_vector_clear(&tmp);
        return;
      }
    }
  }

  ldb_vector_clear(&tmp);

  /* Search other levels. */
  for (level = 1; level < LDB_NUM_LEVELS; level++) {
    size_t num_files = ver->files[level].length;
    uint32_t index;

    if (num_files == 0)
      continue;

    /* Binary search to find earliest index whose largest key >= internal_key */
    index = find_file(&ver->vset->icmp, &ver->files[level], internal_key);

    if (index < num_files) {
      ldb_filemeta_t *f = ver->files[level].items[index];
      ldb_slice_t small_key = ldb_ikey_user_key(&f->smallest);

      if (ldb_compare(ucmp, user_key, &small_key) < 0) {
        /* All of "f" is past any data for user_key. */
      } else {
        if (!func(arg, level, f))
          return;
      }
    }
  }
}

int
ldb_version_get(ldb_version_t *ver,
                const ldb_readopt_t *options,
                const ldb_lkey_t *k,
                ldb_buffer_t *value,
                ldb_getstats_t *stats) {
  getstate_t state;

  stats->seek_file = NULL;
  stats->seek_file_level = -1;

  state.status = LDB_OK;
  state.found = 0;
  state.stats = stats;
  state.last_file_read = NULL;
  state.last_file_read_level = -1;

  state.options = options;
  state.ikey = ldb_lkey_internal_key(k);
  state.vset = ver->vset;

  state.saver.state = S_NOTFOUND;
  state.saver.ucmp = ver->vset->icmp.user_comparator;
  state.saver.user_key = ldb_lkey_user_key(k);
  state.saver.value = value;

  ldb_version_for_each_overlapping(ver,
                                   &state.saver.user_key,
                                   &state.ikey,
                                   &state,
                                   &getstate_match);

  return state.found ? state.status : LDB_NOTFOUND;
}

int
ldb_version_update_stats(ldb_version_t *ver, const ldb_getstats_t *stats) {
  ldb_filemeta_t *f = stats->seek_file;

  if (f != NULL) {
    f->allowed_seeks--;

    if (f->allowed_seeks <= 0 && ver->file_to_compact == NULL) {
      ver->file_to_compact = f;
      ver->file_to_compact_level = stats->seek_file_level;
      return 1;
    }
  }

  return 0;
}

int
ldb_version_record_read_sample(ldb_version_t *ver, const ldb_slice_t *ikey) {
  samplestate_t state;
  ldb_pkey_t pkey;

  if (!ldb_pkey_import(&pkey, ikey))
    return 0;

  state.stats.seek_file = NULL;
  state.stats.seek_file_level = 0;
  state.matches = 0;

  ldb_version_for_each_overlapping(ver,
                                   &pkey.user_key,
                                   ikey,
                                   &state,
                                   &samplestate_match);

  /* Must have at least two matches since we want to merge across
     files. But what if we have a single file that contains many
     overwrites and deletions? Should we have another mechanism for
     finding such files? */
  if (state.matches >= 2) {
    /* 1MB cost is about 1 seek (see comment in builder_apply). */
    return ldb_version_update_stats(ver, &state.stats);
  }

  return 0;
}

void
ldb_version_ref(ldb_version_t *ver) {
  ++ver->refs;
}

void
ldb_version_unref(ldb_version_t *ver) {
  assert(ver != &ver->vset->dummy_versions);
  assert(ver->refs >= 1);

  --ver->refs;

  if (ver->refs == 0)
    ldb_version_destroy(ver);
}

int
ldb_version_overlap_in_level(ldb_version_t *ver,
                             int level,
                             const ldb_slice_t *smallest_user_key,
                             const ldb_slice_t *largest_user_key) {
  return some_file_overlaps_range(&ver->vset->icmp,
                                  (level > 0),
                                  &ver->files[level],
                                  smallest_user_key,
                                  largest_user_key);
}

int
ldb_version_pick_level_for_memtable_output(ldb_version_t *ver,
                                           const ldb_slice_t *small_key,
                                           const ldb_slice_t *large_key) {
  int level = 0;
  int64_t sum;

  if (!ldb_version_overlap_in_level(ver, 0, small_key, large_key)) {
    /* Push to next level if there is no overlap in next level,
       and the #bytes overlapping in the level after that are limited. */
    ldb_vector_t overlaps; /* ldb_filemeta_t */
    ldb_ikey_t start, limit;

    ldb_vector_init(&overlaps);
    ldb_ikey_init(&start);
    ldb_ikey_init(&limit);

    ldb_ikey_set(&start, small_key, LDB_MAX_SEQUENCE, LDB_VALTYPE_SEEK);
    ldb_ikey_set(&limit, large_key, 0, (ldb_valtype_t)0);

    while (level < LDB_MAX_MEM_COMPACT_LEVEL) {
      if (ldb_version_overlap_in_level(ver, level + 1, small_key, large_key))
        break;

      if (level + 2 < LDB_NUM_LEVELS) {
        /* Check that file does not overlap too many grandparent bytes. */
        ldb_version_get_overlapping_inputs(ver, level + 2,
                                           &start, &limit,
                                           &overlaps);

        sum = total_file_size(&overlaps);

        if (sum > max_grandparent_overlap_bytes(ver->vset->options))
          break;
      }

      level++;
    }

    ldb_vector_clear(&overlaps);
    ldb_ikey_clear(&start);
    ldb_ikey_clear(&limit);
  }

  return level;
}

/* Store in "*inputs" all files in "level" that overlap [begin,end]. */
void
ldb_version_get_overlapping_inputs(ldb_version_t *ver,
                                   int level,
                                   const ldb_ikey_t *begin,
                                   const ldb_ikey_t *end,
                                   ldb_vector_t *inputs) {
  const ldb_comparator_t *uc = ver->vset->icmp.user_comparator;
  ldb_slice_t user_begin, user_end;
  size_t i;

  assert(level >= 0);
  assert(level < LDB_NUM_LEVELS);

  ldb_slice_init(&user_begin);
  ldb_slice_init(&user_end);

  ldb_vector_reset(inputs);

  if (begin != NULL)
    user_begin = ldb_ikey_user_key(begin);

  if (end != NULL)
    user_end = ldb_ikey_user_key(end);

  for (i = 0; i < ver->files[level].length;) {
    ldb_filemeta_t *f = ver->files[level].items[i++];
    ldb_slice_t file_start = ldb_ikey_user_key(&f->smallest);
    ldb_slice_t file_limit = ldb_ikey_user_key(&f->largest);

    if (begin != NULL && ldb_compare(uc, &file_limit, &user_begin) < 0) {
      /* "f" is completely before specified range; skip it. */
    } else if (end != NULL && ldb_compare(uc, &file_start, &user_end) > 0) {
      /* "f" is completely after specified range; skip it. */
    } else {
      ldb_vector_push(inputs, f);

      if (level == 0) {
        /* Level-0 files may overlap each other. So check if the newly
           added file has expanded the range. If so, restart search. */
        if (begin != NULL && ldb_compare(uc, &file_start, &user_begin) < 0) {
          user_begin = file_start;
          ldb_vector_reset(inputs);
          i = 0;
        } else if (end != NULL && ldb_compare(uc, &file_limit, &user_end) > 0) {
          user_end = file_limit;
          ldb_vector_reset(inputs);
          i = 0;
        }
      }
    }
  }
}

void
ldb_version_debug(ldb_buffer_t *z, const ldb_version_t *x) {
  int level;

  for (level = 0; level < LDB_NUM_LEVELS; level++) {
    const ldb_vector_t *files = &x->files[level];
    size_t i;

    /* E.g.,
     *   --- level 1 ---
     *   17:123['a' .. 'd']
     *   20:43['e' .. 'g']
     */
    ldb_buffer_string(z, "--- level ");
    ldb_buffer_number(z, level);
    ldb_buffer_string(z, " ---\n");

    for (i = 0; i < files->length; i++) {
      const ldb_filemeta_t *file = files->items[i];

      ldb_buffer_push(z, ' ');
      ldb_buffer_number(z, file->number);
      ldb_buffer_push(z, ':');
      ldb_buffer_number(z, file->file_size);
      ldb_buffer_push(z, '[');
      ldb_ikey_debug(z, &file->smallest);
      ldb_buffer_string(z, " .. ");
      ldb_ikey_debug(z, &file->largest);
      ldb_buffer_string(z, "]\n");
    }
  }
}

/*
 * VersionSet::Builder
 */

/* A helper class so we can efficiently apply a whole sequence
   of edits to a particular state without creating intermediate
   versions that contain full copies of the intermediate state. */
typedef struct level_state_s {
  rb_set64_t deleted_files;
  rb_set_t added_files; /* ldb_filemeta_t * */
} level_state_t;

typedef struct builder_s {
  ldb_vset_t *vset;
  ldb_version_t *base;
  level_state_t levels[LDB_NUM_LEVELS];
} builder_t;

static int
by_smallest_key(const ldb_comparator_t *cmp,
                const ldb_filemeta_t *f1,
                const ldb_filemeta_t *f2) {
  int r = ldb_compare(cmp, &f1->smallest, &f2->smallest);

  if (r != 0)
    return r;

  /* Break ties by file number. */
  if (f1->number == f2->number)
    return 0;

  return f1->number < f2->number ? -1 : 1;
}

static int
file_set_compare(rb_val_t x, rb_val_t y, void *arg) {
  return by_smallest_key(arg, x.p, y.p);
}

static void
file_set_destruct(rb_node_t *node) {
  ldb_filemeta_unref(node->key.p);
}

/* Initialize a builder with the files from *base and other info from *vset. */
static void
builder_init(builder_t *b, ldb_vset_t *vset, ldb_version_t *base) {
  int level;

  b->vset = vset;
  b->base = base;

  for (level = 0; level < LDB_NUM_LEVELS; level++) {
    level_state_t *state = &b->levels[level];

    rb_set64_init(&state->deleted_files);
    rb_set_init(&state->added_files, file_set_compare, &b->vset->icmp);
  }

  ldb_version_ref(b->base);
}

static void
builder_clear(builder_t *b) {
  int level;

  for (level = 0; level < LDB_NUM_LEVELS; level++) {
    level_state_t *state = &b->levels[level];

    rb_set64_clear(&state->deleted_files);
    rb_set_clear(&state->added_files, file_set_destruct);
  }

  ldb_version_unref(b->base);
}

/* Apply all of the edits in *edit to the current state. */
static void
builder_apply(builder_t *b, const ldb_vedit_t *edit) {
  ldb_vset_t *v = b->vset;
  void *item;
  size_t i;

  /* Update compaction pointers. */
  for (i = 0; i < edit->compact_pointers.length; i++) {
    const ikey_entry_t *entry = edit->compact_pointers.items[i];

    ldb_buffer_copy(&v->compact_pointer[entry->level], &entry->key);
  }

  /* Delete files. */
  rb_set_iterate(&edit->deleted_files, item) {
    const file_entry_t *entry = item;
    level_state_t *state = &b->levels[entry->level];

#ifndef NDEBUG
    assert(rb_set64_put(&state->deleted_files, entry->number) == 1);
#else
    rb_set64_put(&state->deleted_files, entry->number);
#endif
  }

  /* Add new files. */
  for (i = 0; i < edit->new_files.length; i++) {
    const meta_entry_t *entry = edit->new_files.items[i];
    level_state_t *state = &b->levels[entry->level];
    ldb_filemeta_t *f = ldb_filemeta_clone(&entry->meta);

    f->refs = 1;

    /* We arrange to automatically compact this file after
     * a certain number of seeks. Let's assume:
     *
     *   (1) One seek costs 10ms
     *   (2) Writing or reading 1MB costs 10ms (100MB/s)
     *   (3) A compaction of 1MB does 25MB of IO:
     *         1MB read from this level
     *         10-12MB read from next level (boundaries may be misaligned)
     *         10-12MB written to next level
     *
     * This implies that 25 seeks cost the same as the compaction
     * of 1MB of data. I.e., one seek costs approximately the
     * same as the compaction of 40KB of data. We are a little
     * conservative and allow approximately one seek for every 16KB
     * of data before triggering a compaction.
     */
    f->allowed_seeks = (int)(f->file_size / 16384U);

    if (f->allowed_seeks < 100)
      f->allowed_seeks = 100;

    rb_set64_del(&state->deleted_files, f->number);
    rb_set_put(&state->added_files, f);
  }
}

static void
builder_maybe_add_file(builder_t *b,
                       ldb_version_t *v,
                       int level,
                       ldb_filemeta_t *f) {
  level_state_t *state = &b->levels[level];

  if (rb_set64_has(&state->deleted_files, f->number)) {
    /* File is deleted: do nothing. */
  } else {
    ldb_vector_t *files = &v->files[level];

#ifndef NDEBUG
    if (level > 0 && files->length > 0) {
      ldb_filemeta_t *item = files->items[files->length - 1];

      /* Must not overlap. */
      assert(ldb_compare(&b->vset->icmp, &item->largest, &f->smallest) < 0);
    }
#endif

    ldb_filemeta_ref(f);
    ldb_vector_push(files, f);
  }
}

/* Save the current state in *v. */
static void
builder_save_to(builder_t *b, ldb_version_t *v) {
  int level;

  for (level = 0; level < LDB_NUM_LEVELS; level++) {
    /* Merge the set of added files with the set of pre-existing files. */
    /* Drop any deleted files. Store the result in *v. */
    const ldb_vector_t *base_files = &b->base->files[level];
    const rb_set_t *added_files = &b->levels[level].added_files;
    size_t i = 0;
    void *item;

    ldb_vector_grow(&v->files[level], base_files->length + added_files->size);

    rb_set_iterate(added_files, item) {
      ldb_filemeta_t *added_file = item;

      /* Add all smaller files listed in b->base. */
      /* This code assumes the base files are sorted. */
      for (; i < base_files->length; i++) {
        ldb_filemeta_t *base_file = base_files->items[i];

        if (by_smallest_key(&b->vset->icmp, base_file, added_file) >= 0)
          break;

        builder_maybe_add_file(b, v, level, base_file);
      }

      builder_maybe_add_file(b, v, level, added_file);
    }

    /* Add remaining base files. */
    for (; i < base_files->length; i++) {
      ldb_filemeta_t *base_file = base_files->items[i];

      builder_maybe_add_file(b, v, level, base_file);
    }

#ifndef NDEBUG
    /* Make sure there is no overlap in levels > 0. */
    if (level > 0) {
      for (i = 1; i < v->files[level].length; i++) {
        const ldb_filemeta_t *x = v->files[level].items[i - 1];
        const ldb_filemeta_t *y = v->files[level].items[i];

        if (ldb_compare(&b->vset->icmp, &x->largest, &y->smallest) >= 0) {
          fprintf(stderr, "overlapping ranges in same level\n");
          abort();
        }
      }
    }
#endif
  }
}

/*
 * VersionSet
 */

static void
ldb_vset_append_version(ldb_vset_t *vset, ldb_version_t *v);

static void
ldb_vset_init(ldb_vset_t *vset,
              const char *dbname,
              const ldb_dbopt_t *options,
              ldb_tcache_t *table_cache,
              const ldb_comparator_t *cmp) {
  int level;

  vset->dbname = dbname;
  vset->options = options;
  vset->table_cache = table_cache;
  vset->icmp = *cmp;
  vset->next_file_number = 2;
  vset->manifest_file_number = 0; /* Filled by recover(). */
  vset->last_sequence = 0;
  vset->log_number = 0;
  vset->prev_log_number = 0;
  vset->descriptor_file = NULL;
  vset->descriptor_log = NULL;
  vset->current = NULL;

  ldb_version_init(&vset->dummy_versions, vset);

  for (level = 0; level < LDB_NUM_LEVELS; level++)
    ldb_buffer_init(&vset->compact_pointer[level]);

  ldb_vset_append_version(vset, ldb_version_create(vset));
}

static void
ldb_vset_clear(ldb_vset_t *vset) {
  int level;

  ldb_version_unref(vset->current);

  assert(vset->dummy_versions.next == &vset->dummy_versions); /* List must be empty. */

  if (vset->descriptor_log != NULL)
    ldb_logwriter_destroy(vset->descriptor_log);

  if (vset->descriptor_file != NULL)
    ldb_wfile_destroy(vset->descriptor_file);

  for (level = 0; level < LDB_NUM_LEVELS; level++)
    ldb_buffer_clear(&vset->compact_pointer[level]);
}

ldb_vset_t *
ldb_vset_create(const char *dbname,
                const ldb_dbopt_t *options,
                ldb_tcache_t *table_cache,
                const ldb_comparator_t *cmp) {
  ldb_vset_t *vset = ldb_malloc(sizeof(ldb_vset_t));
  ldb_vset_init(vset, dbname, options, table_cache, cmp);
  return vset;
}

void
ldb_vset_destroy(ldb_vset_t *vset) {
  ldb_vset_clear(vset);
  ldb_free(vset);
}

ldb_version_t *
ldb_vset_current(const ldb_vset_t *vset) {
  return vset->current;
}

uint64_t
ldb_vset_manifest_file_number(const ldb_vset_t *vset) {
  return vset->manifest_file_number;
}

uint64_t
ldb_vset_new_file_number(ldb_vset_t *vset) {
  return vset->next_file_number++;
}

void
ldb_vset_reuse_file_number(ldb_vset_t *vset, uint64_t file_number) {
  if (vset->next_file_number == file_number + 1)
    vset->next_file_number = file_number;
}

uint64_t
ldb_vset_last_sequence(const ldb_vset_t *vset) {
  return vset->last_sequence;
}

void
ldb_vset_set_last_sequence(ldb_vset_t *vset, uint64_t s) {
  assert(s >= vset->last_sequence);
  vset->last_sequence = s;
}

uint64_t
ldb_vset_log_number(const ldb_vset_t *vset) {
  return vset->log_number;
}

uint64_t
ldb_vset_prev_log_number(const ldb_vset_t *vset) {
  return vset->prev_log_number;
}

int
ldb_vset_needs_compaction(const ldb_vset_t *vset) {
  ldb_version_t *v = vset->current;
  return (v->compaction_score >= 1) || (v->file_to_compact != NULL);
}

static void
ldb_vset_append_version(ldb_vset_t *vset, ldb_version_t *v) {
  /* Make "v" current. */
  assert(v->refs == 0);
  assert(v != vset->current);

  if (vset->current != NULL)
    ldb_version_unref(vset->current);

  vset->current = v;

  ldb_version_ref(v);

  /* Append to linked list. */
  v->prev = vset->dummy_versions.prev;
  v->next = &vset->dummy_versions;
  v->prev->next = v;
  v->next->prev = v;
}

static void
ldb_vset_finalize(ldb_vset_t *vset, ldb_version_t *v);

static int
ldb_vset_write_snapshot(ldb_vset_t *vset, ldb_logwriter_t *log);

int
ldb_vset_log_and_apply(ldb_vset_t *vset, ldb_vedit_t *edit, ldb_mutex_t *mu) {
  char fname[LDB_PATH_MAX];
  ldb_version_t *v;
  int rc = LDB_OK;

  fname[0] = '\0';

  if (edit->has_log_number) {
    assert(edit->log_number >= vset->log_number);
    assert(edit->log_number < vset->next_file_number);
  } else {
    ldb_vedit_set_log_number(edit, vset->log_number);
  }

  if (!edit->has_prev_log_number)
    ldb_vedit_set_prev_log_number(edit, vset->prev_log_number);

  ldb_vedit_set_next_file(edit, vset->next_file_number);
  ldb_vedit_set_last_sequence(edit, vset->last_sequence);

  v = ldb_version_create(vset);

  {
    builder_t b;

    builder_init(&b, vset, vset->current);
    builder_apply(&b, edit);
    builder_save_to(&b, v);
    builder_clear(&b);
  }

  ldb_vset_finalize(vset, v);

  /* Initialize new descriptor log file if necessary by creating
     a temporary file that contains a snapshot of the current version. */
  if (vset->descriptor_log == NULL) {
    /* No reason to unlock *mu here since we only hit this path in the
       first call to log_and_apply (when opening the database). */
    assert(vset->descriptor_file == NULL);

    if (ldb_desc_filename(fname, sizeof(fname), vset->dbname,
                                                vset->manifest_file_number)) {
      rc = ldb_truncfile_create(fname, &vset->descriptor_file);
    } else {
      rc = LDB_INVALID;
    }

    if (rc == LDB_OK) {
      vset->descriptor_log = ldb_logwriter_create(vset->descriptor_file, 0);

      rc = ldb_vset_write_snapshot(vset, vset->descriptor_log);
    }
  }

  /* Unlock during expensive MANIFEST log write. */
  {
    ldb_mutex_unlock(mu);

    /* Write new record to MANIFEST log. */
    if (rc == LDB_OK) {
      ldb_buffer_t record;

      ldb_buffer_init(&record);
      ldb_vedit_export(&record, edit);

      rc = ldb_logwriter_add_record(vset->descriptor_log, &record);

      if (rc == LDB_OK)
        rc = ldb_wfile_sync(vset->descriptor_file);

      if (rc != LDB_OK) {
        ldb_log(vset->options->info_log, "MANIFEST write: %s",
                                         ldb_strerror(rc));
      }

      ldb_buffer_clear(&record);
    }

    /* If we just created a new descriptor file, install it by writing a
       new CURRENT file that points to it. */
    if (rc == LDB_OK && fname[0])
      rc = ldb_set_current_file(vset->dbname, vset->manifest_file_number);

    ldb_mutex_lock(mu);
  }

  /* Install the new version. */
  if (rc == LDB_OK) {
    ldb_vset_append_version(vset, v);

    vset->log_number = edit->log_number;
    vset->prev_log_number = edit->prev_log_number;
  } else {
    ldb_version_destroy(v);

    if (fname[0]) {
      ldb_logwriter_destroy(vset->descriptor_log);
      ldb_wfile_destroy(vset->descriptor_file);

      vset->descriptor_log = NULL;
      vset->descriptor_file = NULL;

      ldb_remove_file(fname);
    }
  }

  return rc;
}

static int
ldb_vset_reuse_manifest(ldb_vset_t *vset, const char *dscname) {
  ldb_filetype_t manifest_type;
  uint64_t manifest_number;
  uint64_t manifest_size;
  const char *dscbase;
  int rc;

  if (!vset->options->reuse_logs)
    return 0;

  dscbase = ldb_basename(dscname);

  if (!ldb_parse_filename(&manifest_type, &manifest_number, dscbase)
      || manifest_type != LDB_FILE_DESC
      || ldb_file_size(dscname, &manifest_size) != LDB_OK
      /* Make new compacted MANIFEST if old one is too big. */
      || manifest_size >= target_file_size(vset->options)) {
    return 0;
  }

  assert(vset->descriptor_file == NULL);
  assert(vset->descriptor_log == NULL);

  rc = ldb_appendfile_create(dscname, &vset->descriptor_file);

  if (rc != LDB_OK) {
    ldb_log(vset->options->info_log, "Reuse MANIFEST: %s",
                                     ldb_strerror(rc));

    assert(vset->descriptor_file == NULL);

    return 0;
  }

  ldb_log(vset->options->info_log, "Reusing MANIFEST %s", dscname);

  vset->descriptor_log = ldb_logwriter_create(vset->descriptor_file,
                                              manifest_size);

  vset->manifest_file_number = manifest_number;

  return 1;
}

static void
report_corruption(ldb_reporter_t *reporter, size_t bytes, int status) {
  (void)bytes;

  if (*reporter->status == LDB_OK)
    *reporter->status = status;
}

static int
read_current_filename(char *path, size_t size, const char *prefix) {
  ldb_buffer_t data;
  size_t len;
  char *name;
  int rc;

  if (!ldb_current_filename(path, size, prefix))
    return LDB_INVALID;

  ldb_buffer_init(&data);

  rc = ldb_read_file(path, &data);

  if (rc != LDB_OK)
    goto fail;

  name = (char *)data.data;
  len = data.size;

  if (len == 0 || name[len - 1] != '\n') {
    rc = LDB_CORRUPTION; /* "CURRENT file does not end with newline" */
    goto fail;
  }

  name[len - 1] = '\0';

  if (!ldb_join(path, size, prefix, name)) {
    rc = LDB_INVALID;
    goto fail;
  }

fail:
  ldb_buffer_clear(&data);
  return rc;
}

int
ldb_vset_recover(ldb_vset_t *vset, int *save_manifest) {
  const ldb_comparator_t *ucmp = vset->icmp.user_comparator;
  char fname[LDB_PATH_MAX];
  int have_log_number = 0;
  int have_prev_log_number = 0;
  int have_next_file = 0;
  int have_last_sequence = 0;
  uint64_t next_file = 0;
  uint64_t last_sequence = 0;
  uint64_t log_number = 0;
  uint64_t prev_log_number = 0;
  int read_records = 0;
  builder_t builder;
  ldb_rfile_t *file;
  int rc;

  /* Read "CURRENT" file, which contains a
     pointer to the current manifest file. */
  rc = read_current_filename(fname, sizeof(fname), vset->dbname);

  if (rc != LDB_OK)
    return rc;

  rc = ldb_seqfile_create(fname, &file);

  if (rc != LDB_OK) {
    if (rc == LDB_NOTFOUND)
      return LDB_CORRUPTION; /* "CURRENT points to a non-existent file" */

    return rc;
  }

  builder_init(&builder, vset, vset->current);

  {
    ldb_slice_t name = ldb_string(ucmp->name);
    ldb_reporter_t reporter;
    ldb_logreader_t reader;
    ldb_slice_t record;
    ldb_buffer_t buf;
    ldb_vedit_t edit;

    reporter.status = &rc;
    reporter.corruption = report_corruption;

    ldb_logreader_init(&reader, file, &reporter, 1, 0);
    ldb_slice_init(&record);
    ldb_buffer_init(&buf);
    ldb_vedit_init(&edit);

    while (ldb_logreader_read_record(&reader, &record, &buf) && rc == LDB_OK) {
      ++read_records;

      /* Calls ldb_vedit_reset() internally. */
      if (!ldb_vedit_import(&edit, &record))
        rc = LDB_CORRUPTION;

      if (rc == LDB_OK) {
        if (edit.has_comparator && !ldb_slice_equal(&edit.comparator, &name)) {
          rc = LDB_INVALID; /* "[edit.comparator] does not match
                                existing comparator [vset.user_comparator]" */
        }
      }

      if (rc == LDB_OK)
        builder_apply(&builder, &edit);

      if (edit.has_log_number) {
        log_number = edit.log_number;
        have_log_number = 1;
      }

      if (edit.has_prev_log_number) {
        prev_log_number = edit.prev_log_number;
        have_prev_log_number = 1;
      }

      if (edit.has_next_file_number) {
        next_file = edit.next_file_number;
        have_next_file = 1;
      }

      if (edit.has_last_sequence) {
        last_sequence = edit.last_sequence;
        have_last_sequence = 1;
      }
    }

    ldb_vedit_clear(&edit);
    ldb_buffer_clear(&buf);
    ldb_logreader_clear(&reader);
  }

  ldb_rfile_destroy(file);
  file = NULL;

  if (rc == LDB_OK) {
    if (!have_next_file)
      rc = LDB_CORRUPTION; /* "no meta-nextfile entry in descriptor" */
    else if (!have_log_number)
      rc = LDB_CORRUPTION; /* "no meta-lognumber entry in descriptor" */
    else if (!have_last_sequence)
      rc = LDB_CORRUPTION; /* "no last-sequence-number entry in descriptor" */

    if (!have_prev_log_number)
      prev_log_number = 0;

    ldb_vset_mark_file_number_used(vset, prev_log_number);
    ldb_vset_mark_file_number_used(vset, log_number);
  }

  if (rc == LDB_OK) {
    ldb_version_t *v = ldb_version_create(vset);

    builder_save_to(&builder, v);

    /* Install recovered version. */
    ldb_vset_finalize(vset, v);
    ldb_vset_append_version(vset, v);

    vset->manifest_file_number = next_file;
    vset->next_file_number = next_file + 1;
    vset->last_sequence = last_sequence;
    vset->log_number = log_number;
    vset->prev_log_number = prev_log_number;

    /* See if we can reuse the existing MANIFEST file. */
    if (ldb_vset_reuse_manifest(vset, fname)) {
      /* No need to save new manifest. */
    } else {
      *save_manifest = 1;
    }
  } else {
    ldb_log(vset->options->info_log,
            "Error recovering version set with %d records: %s",
            read_records, ldb_strerror(rc));
  }

  builder_clear(&builder);

  return rc;
}

void
ldb_vset_mark_file_number_used(ldb_vset_t *vset, uint64_t number) {
  if (vset->next_file_number <= number)
    vset->next_file_number = number + 1;
}

static void
ldb_vset_finalize(ldb_vset_t *vset, ldb_version_t *v) {
  /* Precomputed best level for next compaction. */
  int best_level = -1;
  double best_score = -1;
  int level;

  for (level = 0; level < LDB_NUM_LEVELS - 1; level++) {
    double score;

    if (level == 0) {
      /* We treat level-0 specially by bounding the number of files
       * instead of number of bytes for two reasons:
       *
       * (1) With larger write-buffer sizes, it is nice not to do too
       * many level-0 compactions.
       *
       * (2) The files in level-0 are merged on every read and
       * therefore we wish to avoid too many files when the individual
       * file size is small (perhaps because of a small write-buffer
       * setting, or very high compression ratios, or lots of
       * overwrites/deletions).
       */
      score = v->files[level].length / (double)(LDB_L0_COMPACTION_TRIGGER);
    } else {
      /* Compute the ratio of current size to size limit. */
      uint64_t level_bytes = total_file_size(&v->files[level]);

      score = (double)level_bytes / max_bytes_for_level(vset->options, level);
    }

    if (score > best_score) {
      best_level = level;
      best_score = score;
    }
  }

  v->compaction_level = best_level;
  v->compaction_score = best_score;
}

static int
ldb_vset_write_snapshot(ldb_vset_t *vset, ldb_logwriter_t *log) {
  ldb_buffer_t record;
  ldb_vedit_t edit;
  int level, rc;

  /* Save metadata. */
  ldb_vedit_init(&edit);
  ldb_vedit_set_comparator_name(&edit, vset->icmp.user_comparator->name);

  /* Save compaction pointers. */
  for (level = 0; level < LDB_NUM_LEVELS; level++) {
    if (vset->compact_pointer[level].size > 0)
      ldb_vedit_set_compact_pointer(&edit, level,
                                    &vset->compact_pointer[level]);
  }

  /* Save files. */
  for (level = 0; level < LDB_NUM_LEVELS; level++) {
    const ldb_vector_t *files = &vset->current->files[level];
    size_t i;

    for (i = 0; i < files->length; i++) {
      const ldb_filemeta_t *f = files->items[i];

      ldb_vedit_add_file(&edit, level,
                         f->number,
                         f->file_size,
                         &f->smallest,
                         &f->largest);
    }
  }

  ldb_buffer_init(&record);
  ldb_vedit_export(&record, &edit);
  ldb_vedit_clear(&edit);

  rc = ldb_logwriter_add_record(log, &record);

  ldb_buffer_clear(&record);

  return rc;
}

int
ldb_vset_num_level_files(const ldb_vset_t *vset, int level) {
  assert(level >= 0);
  assert(level < LDB_NUM_LEVELS);
  return vset->current->files[level].length;
}

const char *
ldb_vset_level_summary(const ldb_vset_t *vset, char *scratch) {
  const ldb_version_t *c = vset->current;

  /* Update code if kNumLevels changes. */
  STATIC_ASSERT(LDB_NUM_LEVELS == 7);

  sprintf(scratch, "files[ %d %d %d %d %d %d %d ]",
                   (int)c->files[0].length,
                   (int)c->files[1].length,
                   (int)c->files[2].length,
                   (int)c->files[3].length,
                   (int)c->files[4].length,
                   (int)c->files[5].length,
                   (int)c->files[6].length);

  return scratch;
}

uint64_t
ldb_vset_approximate_offset_of(ldb_vset_t *vset,
                               ldb_version_t *v,
                               const ldb_ikey_t *ikey) {
  uint64_t result = 0;
  int level;

  for (level = 0; level < LDB_NUM_LEVELS; level++) {
    const ldb_vector_t *files = &v->files[level];
    size_t i;

    for (i = 0; i < files->length; i++) {
      const ldb_filemeta_t *file = files->items[i];

      if (ldb_compare(&vset->icmp, &file->largest, ikey) <= 0) {
        /* Entire file is before "ikey", so just add the file size. */
        result += file->file_size;
      } else if (ldb_compare(&vset->icmp, &file->smallest, ikey) > 0) {
        /* Entire file is after "ikey", so ignore. */
        if (level > 0) {
          /* Files other than level 0 are sorted by meta->smallest, so
             no further files in this level will contain data for
             "ikey". */
          break;
        }
      } else {
        /* "ikey" falls in the range for this table. Add the
           approximate offset of "ikey" within the table. */
        ldb_table_t *tableptr;
        ldb_iter_t *iter;

        iter = ldb_tcache_iterate(vset->table_cache,
                                  ldb_readopt_default,
                                  file->number,
                                  file->file_size,
                                  &tableptr);

        if (tableptr != NULL)
          result += ldb_table_approximate_offsetof(tableptr, ikey);

        ldb_iter_destroy(iter);
      }
    }
  }

  return result;
}

void
ldb_vset_add_live_files(ldb_vset_t *vset, rb_set64_t *live) {
  ldb_version_t *list = &vset->dummy_versions;
  ldb_version_t *v;
  int level;
  size_t i;

  for (v = list->next; v != list; v = v->next) {
    for (level = 0; level < LDB_NUM_LEVELS; level++) {
      const ldb_vector_t *files = &v->files[level];

      for (i = 0; i < files->length; i++) {
        const ldb_filemeta_t *file = files->items[i];

        rb_set64_put(live, file->number);
      }
    }
  }
}

int64_t
ldb_vset_num_level_bytes(const ldb_vset_t *vset, int level) {
  assert(level >= 0);
  assert(level < LDB_NUM_LEVELS);
  return total_file_size(&vset->current->files[level]);
}

int64_t
ldb_vset_max_next_level_overlapping_bytes(ldb_vset_t *vset) {
  ldb_vector_t overlaps;
  int64_t result = 0;
  int level;
  size_t i;

  ldb_vector_init(&overlaps);

  for (level = 1; level < LDB_NUM_LEVELS - 1; level++) {
    for (i = 0; i < vset->current->files[level].length; i++) {
      const ldb_filemeta_t *f = vset->current->files[level].items[i];
      int64_t sum;

      ldb_version_get_overlapping_inputs(vset->current,
                                         level + 1,
                                         &f->smallest,
                                         &f->largest,
                                         &overlaps);

      sum = total_file_size(&overlaps);

      if (sum > result)
        result = sum;
    }
  }

  ldb_vector_clear(&overlaps);

  return result;
}

/* Stores the minimal range that covers all entries in inputs in
   *smallest, *largest. */
/* REQUIRES: inputs is not empty */
static void
ldb_vset_get_range(ldb_vset_t *vset,
                   const ldb_vector_t *inputs,
                   ldb_slice_t *smallest,
                   ldb_slice_t *largest) {
  ldb_ikey_t *small = NULL;
  ldb_ikey_t *large = NULL;
  size_t i;

  assert(inputs->length > 0);

  for (i = 0; i < inputs->length; i++) {
    ldb_filemeta_t *f = inputs->items[i];

    if (i == 0) {
      small = &f->smallest;
      large = &f->largest;
    } else {
      if (ldb_compare(&vset->icmp, &f->smallest, small) < 0)
        small = &f->smallest;

      if (ldb_compare(&vset->icmp, &f->largest, large) > 0)
        large = &f->largest;
    }
  }

  *smallest = *small;
  *largest = *large;
}

/* Stores the minimal range that covers all entries in inputs1 and inputs2
   in *smallest, *largest. */
/* REQUIRES: inputs is not empty */
static void
ldb_vset_get_range2(ldb_vset_t *vset,
                    const ldb_vector_t *inputs1,
                    const ldb_vector_t *inputs2,
                    ldb_slice_t *smallest,
                    ldb_slice_t *largest) {
  ldb_vector_t all;
  size_t i;

  ldb_vector_init(&all);
  ldb_vector_grow(&all, inputs1->length + inputs2->length);

  for (i = 0; i < inputs1->length; i++)
    all.items[all.length++] = inputs1->items[i];

  for (i = 0; i < inputs2->length; i++)
    all.items[all.length++] = inputs2->items[i];

  ldb_vset_get_range(vset, &all, smallest, largest);

  ldb_vector_clear(&all);
}

ldb_iter_t *
ldb_inputiter_create(ldb_vset_t *vset, ldb_compaction_t *c) {
  ldb_readopt_t options = *ldb_readopt_default;
  ldb_iter_t *result;
  ldb_iter_t **list;
  int num = 0;
  int space, which;
  size_t i;

  options.verify_checksums = vset->options->paranoid_checks;
  options.fill_cache = 0;

  /* Level-0 files have to be merged together. For other levels,
     we will make a concatenating iterator per level. */
  space = (ldb_compaction_level(c) == 0 ? c->inputs[0].length + 1 : 2);
  list = ldb_malloc(space * sizeof(ldb_iter_t *));

  for (which = 0; which < 2; which++) {
    if (c->inputs[which].length > 0) {
      if (ldb_compaction_level(c) + which == 0) {
        const ldb_vector_t *files = &c->inputs[which];

        for (i = 0; i < files->length; i++) {
          const ldb_filemeta_t *file = files->items[i];

          list[num++] = ldb_tcache_iterate(vset->table_cache,
                                           &options,
                                           file->number,
                                           file->file_size,
                                           NULL);
        }
      } else {
        /* Create concatenating iterator for the files from this level. */
        list[num++] = ldb_twoiter_create(ldb_numiter_create(&vset->icmp,
                                                            &c->inputs[which]),
                                         &get_file_iterator,
                                         vset->table_cache,
                                         &options);
      }
    }
  }

  assert(num <= space);

  result = ldb_mergeiter_create(&vset->icmp, list, num);

  ldb_free(list);

  return result;
}

static void
ldb_vset_setup_other_inputs(ldb_vset_t *vset, ldb_compaction_t *c);

ldb_compaction_t *
ldb_vset_pick_compaction(ldb_vset_t *vset) {
  ldb_compaction_t *c;
  int level;
  size_t i;

  /* We prefer compactions triggered by too much data in a level over
     the compactions triggered by seeks. */
  int size_compaction = (vset->current->compaction_score >= 1);
  int seek_compaction = (vset->current->file_to_compact != NULL);

  if (size_compaction) {
    level = vset->current->compaction_level;

    assert(level >= 0);
    assert(level + 1 < LDB_NUM_LEVELS);

    c = ldb_compaction_create(vset->options, level);

    /* Pick the first file that comes after compact_pointer[level]. */
    for (i = 0; i < vset->current->files[level].length; i++) {
      ldb_filemeta_t *f = vset->current->files[level].items[i];

      if (vset->compact_pointer[level].size == 0 ||
          ldb_compare(&vset->icmp, &f->largest,
                      &vset->compact_pointer[level]) > 0) {
        ldb_vector_push(&c->inputs[0], f);
        break;
      }
    }

    if (c->inputs[0].length == 0) {
      /* Wrap-around to the beginning of the key space. */
      ldb_vector_push(&c->inputs[0], vset->current->files[level].items[0]);
    }
  } else if (seek_compaction) {
    level = vset->current->file_to_compact_level;
    c = ldb_compaction_create(vset->options, level);
    ldb_vector_push(&c->inputs[0], vset->current->file_to_compact);
  } else {
    return NULL;
  }

  c->input_version = vset->current;

  ldb_version_ref(c->input_version);

  /* Files in level 0 may overlap each other,
     so pick up all overlapping ones. */
  if (level == 0) {
    ldb_slice_t smallest, largest;

    ldb_vset_get_range(vset, &c->inputs[0], &smallest, &largest);

    /* Note that the next call will discard the file we placed in
       c->inputs[0] earlier and replace it with an overlapping set
       which will include the picked file. */
    ldb_version_get_overlapping_inputs(vset->current, 0,
                                       &smallest, &largest,
                                       &c->inputs[0]);

    assert(c->inputs[0].length > 0);
  }

  ldb_vset_setup_other_inputs(vset, c);

  return c;
}

/* Finds the largest key in a vector of files. Returns true if files is not
   empty. */
static int
find_largest_key(const ldb_comparator_t *icmp,
                 const ldb_vector_t *files,
                 ldb_slice_t *largest_key) {
  ldb_ikey_t *large = NULL;
  size_t i;

  if (files->length == 0)
    return 0;

  for (i = 0; i < files->length; i++) {
    ldb_filemeta_t *f = files->items[i];

    if (i == 0) {
      large = &f->largest;
    } else {
      if (ldb_compare(icmp, &f->largest, large) > 0)
        large = &f->largest;
    }
  }

  *largest_key = *large;

  return 1;
}

/* Finds minimum file b2=(l2, u2) in level file for which l2 > u1 and
   user_key(l2) = user_key(u1). */
static ldb_filemeta_t *
find_smallest_boundary_file(const ldb_comparator_t *icmp,
                            const ldb_vector_t *level_files,
                            const ldb_ikey_t *largest_key) {
  const ldb_comparator_t *user_cmp = icmp->user_comparator;
  ldb_slice_t user_key = ldb_ikey_user_key(largest_key);
  ldb_filemeta_t *res = NULL;
  ldb_slice_t file_key;
  size_t i;

  for (i = 0; i < level_files->length; ++i) {
    ldb_filemeta_t *f = level_files->items[i];

    if (ldb_compare(icmp, &f->smallest, largest_key) <= 0)
      continue;

    file_key = ldb_ikey_user_key(&f->smallest);

    if (ldb_compare(user_cmp, &file_key, &user_key) == 0) {
      if (res == NULL || ldb_compare(icmp, &f->smallest, &res->smallest) < 0)
        res = f;
    }
  }

  return res;
}

/* Extracts the largest file b1 from |compaction_files| and then searches for a
 * b2 in |level_files| for which user_key(u1) = user_key(l2). If it finds such a
 * file b2 (known as a boundary file) it adds it to |compaction_files| and then
 * searches again using this new upper bound.
 *
 * If there are two blocks, b1=(l1, u1) and b2=(l2, u2) and
 * user_key(u1) = user_key(l2), and if we compact b1 but not b2 then a
 * subsequent get operation will yield an incorrect result because it will
 * return the record from b2 in level i rather than from b1 because it searches
 * level by level for records matching the supplied user key.
 *
 * parameters:
 *   in     level_files:      List of files to search for boundary files.
 *   in/out compaction_files: List of files to extend by adding boundary files.
 */
void
add_boundary_inputs(const ldb_comparator_t *icmp,
                    const ldb_vector_t *level_files,
                    ldb_vector_t *compaction_files) {
  ldb_slice_t largest_key;
  int search = 1;

  /* Quick return if compaction_files is empty. */
  if (!find_largest_key(icmp, compaction_files, &largest_key))
    return;

  while (search) {
    ldb_filemeta_t *file = find_smallest_boundary_file(icmp,
                                                       level_files,
                                                       &largest_key);

    /* If a boundary file was found advance
       largest_key, otherwise we're done. */
    if (file != NULL) {
      ldb_vector_push(compaction_files, file);
      largest_key = file->largest;
    } else {
      search = 0;
    }
  }
}

static void
ldb_vset_setup_other_inputs(ldb_vset_t *vset, ldb_compaction_t *c) {
  int level = ldb_compaction_level(c);
  ldb_slice_t smallest, largest;
  ldb_slice_t all_start, all_limit;

  add_boundary_inputs(&vset->icmp,
                      &vset->current->files[level],
                      &c->inputs[0]);

  ldb_vset_get_range(vset, &c->inputs[0], &smallest, &largest);

  ldb_version_get_overlapping_inputs(vset->current, level + 1,
                                     &smallest, &largest,
                                     &c->inputs[1]);

  add_boundary_inputs(&vset->icmp,
                      &vset->current->files[level + 1],
                      &c->inputs[1]);

  /* Get entire range covered by compaction. */
  ldb_vset_get_range2(vset, &c->inputs[0], &c->inputs[1],
                            &all_start, &all_limit);

  /* See if we can grow the number of inputs in "level" without
     changing the number of "level+1" files we pick up. */
  if (c->inputs[1].length > 0) {
    ldb_vector_t expanded0;
    int64_t inputs0_size;
    int64_t inputs1_size;
    int64_t expanded0_size;

    ldb_vector_init(&expanded0);

    ldb_version_get_overlapping_inputs(vset->current, level,
                                       &all_start, &all_limit,
                                       &expanded0);

    add_boundary_inputs(&vset->icmp, &vset->current->files[level], &expanded0);

    inputs0_size = total_file_size(&c->inputs[0]);
    inputs1_size = total_file_size(&c->inputs[1]);
    expanded0_size = total_file_size(&expanded0);

    if (expanded0.length > c->inputs[0].length &&
        inputs1_size + expanded0_size <
            expanded_compaction_byte_size_limit(vset->options)) {
      ldb_slice_t new_start, new_limit;
      ldb_vector_t expanded1;

      ldb_vector_init(&expanded1);

      ldb_vset_get_range(vset, &expanded0, &new_start, &new_limit);

      ldb_version_get_overlapping_inputs(vset->current,
                                         level + 1,
                                         &new_start,
                                         &new_limit,
                                         &expanded1);

      add_boundary_inputs(&vset->icmp,
                          &vset->current->files[level + 1],
                          &expanded1);

      if (expanded1.length == c->inputs[1].length) {
        ldb_log(vset->options->info_log,
                "Expanding@%d %d+%d (%ld+%ld bytes) "
                "to %d+%d (%ld+%ld bytes)", level,
                (int)c->inputs[0].length,
                (int)c->inputs[1].length,
                (long)inputs0_size,
                (long)inputs1_size,
                (int)expanded0.length,
                (int)expanded1.length,
                (long)expanded0_size,
                (long)inputs1_size);

        smallest = new_start;
        largest = new_limit;

        ldb_vector_swap(&c->inputs[0], &expanded0);
        ldb_vector_swap(&c->inputs[1], &expanded1);

        ldb_vset_get_range2(vset, &c->inputs[0], &c->inputs[1],
                                  &all_start, &all_limit);
      }

      ldb_vector_clear(&expanded1);
    }

    ldb_vector_clear(&expanded0);
  }

  /* Compute the set of grandparent files that overlap this compaction
     (parent == level+1; grandparent == level+2). */
  if (level + 2 < LDB_NUM_LEVELS) {
    ldb_version_get_overlapping_inputs(vset->current, level + 2,
                                       &all_start, &all_limit,
                                       &c->grandparents);
  }

  /* Update the place where we will do the next compaction for this level.
     We update this immediately instead of waiting for the VersionEdit
     to be applied so that if the compaction fails, we will try a different
     key range next time. */
  ldb_buffer_copy(&vset->compact_pointer[level], &largest);

  ldb_vedit_set_compact_pointer(&c->edit, level, &largest);
}

ldb_compaction_t *
ldb_vset_compact_range(ldb_vset_t *vset,
                       int level,
                       const ldb_ikey_t *begin,
                       const ldb_ikey_t *end) {
  ldb_vector_t inputs;
  ldb_compaction_t *c;

  ldb_vector_init(&inputs);

  ldb_version_get_overlapping_inputs(vset->current, level, begin, end, &inputs);

  if (inputs.length == 0)
    return NULL;

  /* Avoid compacting too much in one shot in case the range is large.
     But we cannot do this for level-0 since level-0 files can overlap
     and we must not pick one file and drop another older file if the
     two files overlap. */
  if (level > 0) {
    uint64_t limit = max_file_size_for_level(vset->options, level);
    uint64_t total = 0;
    size_t i;

    for (i = 0; i < inputs.length; i++) {
      ldb_filemeta_t *f = inputs.items[i];

      total += f->file_size;

      if (total >= limit) {
        ldb_vector_resize(&inputs, i + 1);
        break;
      }
    }
  }

  c = ldb_compaction_create(vset->options, level);

  c->input_version = vset->current;

  ldb_version_ref(c->input_version);

  ldb_vector_swap(&c->inputs[0], &inputs);

  ldb_vset_setup_other_inputs(vset, c);

  ldb_vector_clear(&inputs);

  return c;
}

/*
 * Compaction
 */

static void
ldb_compaction_init(ldb_compaction_t *c,
                    const ldb_dbopt_t *options,
                    int level) {
  int i;

  c->level = level;
  c->max_output_file_size = max_file_size_for_level(options, level);
  c->input_version = NULL;
  c->grandparent_index = 0;
  c->seen_key = 0;
  c->overlapped_bytes = 0;

  for (i = 0; i < LDB_NUM_LEVELS; i++)
    c->level_ptrs[i] = 0;

  ldb_vedit_init(&c->edit);
  ldb_vector_init(&c->inputs[0]);
  ldb_vector_init(&c->inputs[1]);
  ldb_vector_init(&c->grandparents);
}

static void
ldb_compaction_clear(ldb_compaction_t *c) {
  if (c->input_version != NULL)
    ldb_version_unref(c->input_version);

  ldb_vedit_clear(&c->edit);
  ldb_vector_clear(&c->inputs[0]);
  ldb_vector_clear(&c->inputs[1]);
  ldb_vector_clear(&c->grandparents);
}

ldb_compaction_t *
ldb_compaction_create(const ldb_dbopt_t *options, int level) {
  ldb_compaction_t *c = ldb_malloc(sizeof(ldb_compaction_t));
  ldb_compaction_init(c, options, level);
  return c;
}

void
ldb_compaction_destroy(ldb_compaction_t *c) {
  ldb_compaction_clear(c);
  ldb_free(c);
}

int
ldb_compaction_level(const ldb_compaction_t *c) {
  return c->level;
}

ldb_vedit_t *
ldb_compaction_edit(ldb_compaction_t *c) {
  return &c->edit;
}

int
ldb_compaction_num_input_files(const ldb_compaction_t *c, int which) {
  return c->inputs[which].length;
}

ldb_filemeta_t *
ldb_compaction_input(const ldb_compaction_t *c, int which, int i) {
  return c->inputs[which].items[i];
}

uint64_t
ldb_compaction_max_output_file_size(const ldb_compaction_t *c) {
  return c->max_output_file_size;
}

int
ldb_compaction_is_trivial_move(const ldb_compaction_t *c) {
  const ldb_vset_t *vset = c->input_version->vset;

  /* Avoid a move if there is lots of overlapping grandparent data.
     Otherwise, the move could create a parent file that will require
     a very expensive merge later on. */
  return ldb_compaction_num_input_files(c, 0) == 1
      && ldb_compaction_num_input_files(c, 1) == 0
      && total_file_size(&c->grandparents) <=
           max_grandparent_overlap_bytes(vset->options);
}

void
ldb_compaction_add_input_deletions(ldb_compaction_t *c, ldb_vedit_t *edit) {
  int which;
  size_t i;

  for (which = 0; which < 2; which++) {
    for (i = 0; i < c->inputs[which].length; i++) {
      const ldb_filemeta_t *file = c->inputs[which].items[i];

      ldb_vedit_remove_file(edit, c->level + which, file->number);
    }
  }
}

int
ldb_compaction_is_base_level_for_key(ldb_compaction_t *c,
                                     const ldb_slice_t *user_key) {
  /* Maybe use binary search to find right entry instead of linear search? */
  const ldb_comparator_t *user_cmp =
    c->input_version->vset->icmp.user_comparator;
  int lvl;

  for (lvl = c->level + 2; lvl < LDB_NUM_LEVELS; lvl++) {
    ldb_vector_t *files = &c->input_version->files[lvl];

    while (c->level_ptrs[lvl] < files->length) {
      ldb_filemeta_t *f = files->items[c->level_ptrs[lvl]];
      ldb_slice_t key = ldb_ikey_user_key(&f->largest);

      if (ldb_compare(user_cmp, user_key, &key) <= 0) {
        /* We've advanced far enough. */
        key = ldb_ikey_user_key(&f->smallest);

        if (ldb_compare(user_cmp, user_key, &key) >= 0) {
          /* Key falls in this file's range, so definitely not base level. */
          return 0;
        }

        break;
      }

      c->level_ptrs[lvl]++;
    }
  }

  return 1;
}

int
ldb_compaction_should_stop_before(ldb_compaction_t *c,
                                  const ldb_slice_t *ikey) {
  const ldb_vset_t *vset = c->input_version->vset;
  const ldb_comparator_t *icmp = &vset->icmp;

  /* Scan to find earliest grandparent file that contains key. */
  while (c->grandparent_index < c->grandparents.length) {
    ldb_filemeta_t *f = c->grandparents.items[c->grandparent_index];

    if (ldb_compare(icmp, ikey, &f->largest) <= 0)
      break;

    if (c->seen_key)
      c->overlapped_bytes += f->file_size;

    c->grandparent_index++;
  }

  c->seen_key = 1;

  if (c->overlapped_bytes > max_grandparent_overlap_bytes(vset->options)) {
    /* Too much overlap for current output; start new output. */
    c->overlapped_bytes = 0;
    return 1;
  }

  return 0;
}

void
ldb_compaction_release_inputs(ldb_compaction_t *c) {
  if (c->input_version != NULL) {
    ldb_version_unref(c->input_version);
    c->input_version = NULL;
  }
}
