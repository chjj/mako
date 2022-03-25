/*!
 * lcdb_c.h - wrapper for lcdb
 * Copyright (c) 2022, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/lcdb
 *
 * Parts of this software are based on google/leveldb:
 *   Copyright (c) 2011, The LevelDB Authors. All rights reserved.
 *   https://github.com/google/leveldb
 *
 * See LICENSE for more information.
 */

#ifndef LCDB_C_H
#define LCDB_C_H

#ifdef __cplusplus
extern "C" {
#endif

#include <limits.h>
#include <stddef.h>

/*
 * Types
 */

typedef struct ldb_s leveldb_t;
typedef struct ldb_iter_s leveldb_iterator_t;
typedef struct ldb_batch_s leveldb_writebatch_t;
typedef struct ldb_snapshot_s leveldb_snapshot_t;
typedef struct ldb_readopt_s leveldb_readoptions_t;
typedef struct ldb_writeopt_s leveldb_writeoptions_t;
typedef struct ldb_dbopt_s leveldb_options_t;
typedef struct ldb_lru_s leveldb_cache_t;
typedef struct ldb_logger_s leveldb_logger_t;
typedef struct leveldb_comparator_s leveldb_comparator_t;
typedef struct leveldb_filterpolicy_s leveldb_filterpolicy_t;
typedef struct leveldb_env_s leveldb_env_t;

#if defined(UINT64_MAX)
typedef uint64_t ldb_uint64_t;
#elif defined(_WIN32) && !defined(__GNUC__)
typedef unsigned __int64 ldb_uint64_t;
#elif ULONG_MAX >> 31 >> 31 >> 1 == 1
typedef unsigned long ldb_uint64_t;
#else
#  ifdef __GNUC__
__extension__
#  endif
typedef unsigned long long ldb_uint64_t;
#endif

#ifndef LDB_EXTERN
#  define LDB_EXTERN
#endif

/*
 * Constants
 */

enum {
  leveldb_no_compression = 0,
  leveldb_snappy_compression = 1
};

/*
 * Symbol Aliases
 */

#define leveldb_open ldb_c_open
#define leveldb_close ldb_c_close
#define leveldb_put ldb_c_put
#define leveldb_delete ldb_c_delete
#define leveldb_write ldb_c_write
#define leveldb_get ldb_c_get
#define leveldb_create_iterator ldb_c_create_iterator
#define leveldb_create_snapshot ldb_c_create_snapshot
#define leveldb_release_snapshot ldb_c_release_snapshot
#define leveldb_property_value ldb_c_property_value
#define leveldb_approximate_sizes ldb_c_approximate_sizes
#define leveldb_compact_range ldb_c_compact_range
#define leveldb_destroy_db ldb_c_destroy_db
#define leveldb_repair_db ldb_c_repair_db
#define leveldb_iter_destroy ldb_c_iter_destroy
#define leveldb_iter_valid ldb_c_iter_valid
#define leveldb_iter_seek_to_first ldb_c_iter_seek_to_first
#define leveldb_iter_seek_to_last ldb_c_iter_seek_to_last
#define leveldb_iter_seek ldb_c_iter_seek
#define leveldb_iter_next ldb_c_iter_next
#define leveldb_iter_prev ldb_c_iter_prev
#define leveldb_iter_key ldb_c_iter_key
#define leveldb_iter_value ldb_c_iter_value
#define leveldb_iter_get_error ldb_c_iter_get_error
#define leveldb_writebatch_create ldb_c_writebatch_create
#define leveldb_writebatch_destroy ldb_c_writebatch_destroy
#define leveldb_writebatch_clear ldb_c_writebatch_clear
#define leveldb_writebatch_put ldb_c_writebatch_put
#define leveldb_writebatch_delete ldb_c_writebatch_delete
#define leveldb_writebatch_iterate ldb_c_writebatch_iterate
#define leveldb_writebatch_append ldb_c_writebatch_append
#define leveldb_options_create ldb_c_options_create
#define leveldb_options_destroy ldb_c_options_destroy
#define leveldb_options_set_comparator ldb_c_options_set_comparator
#define leveldb_options_set_filter_policy ldb_c_options_set_filter_policy
#define leveldb_options_set_create_if_missing ldb_c_options_set_create_if_missing
#define leveldb_options_set_error_if_exists ldb_c_options_set_error_if_exists
#define leveldb_options_set_paranoid_checks ldb_c_options_set_paranoid_checks
#define leveldb_options_set_env ldb_c_options_set_env
#define leveldb_options_set_info_log ldb_c_options_set_info_log
#define leveldb_options_set_write_buffer_size ldb_c_options_set_write_buffer_size
#define leveldb_options_set_max_open_files ldb_c_options_set_max_open_files
#define leveldb_options_set_cache ldb_c_options_set_cache
#define leveldb_options_set_block_size ldb_c_options_set_block_size
#define leveldb_options_set_block_restart_interval ldb_c_options_set_block_restart_interval
#define leveldb_options_set_max_file_size ldb_c_options_set_max_file_size
#define leveldb_options_set_compression ldb_c_options_set_compression
#define leveldb_comparator_create ldb_c_comparator_create
#define leveldb_comparator_destroy ldb_c_comparator_destroy
#define leveldb_filterpolicy_create ldb_c_filterpolicy_create
#define leveldb_filterpolicy_destroy ldb_c_filterpolicy_destroy
#define leveldb_filterpolicy_create_bloom ldb_c_filterpolicy_create_bloom
#define leveldb_readoptions_create ldb_c_readoptions_create
#define leveldb_readoptions_destroy ldb_c_readoptions_destroy
#define leveldb_readoptions_set_verify_checksums ldb_c_readoptions_set_verify_checksums
#define leveldb_readoptions_set_fill_cache ldb_c_readoptions_set_fill_cache
#define leveldb_readoptions_set_snapshot ldb_c_readoptions_set_snapshot
#define leveldb_writeoptions_create ldb_c_writeoptions_create
#define leveldb_writeoptions_destroy ldb_c_writeoptions_destroy
#define leveldb_writeoptions_set_sync ldb_c_writeoptions_set_sync
#define leveldb_cache_create_lru ldb_c_cache_create_lru
#define leveldb_cache_destroy ldb_c_cache_destroy
#define leveldb_create_default_env ldb_c_create_default_env
#define leveldb_env_destroy ldb_c_env_destroy
#define leveldb_env_get_test_directory ldb_c_env_get_test_directory
#define leveldb_free ldb_c_free
#define leveldb_major_version ldb_c_major_version
#define leveldb_minor_version ldb_c_minor_version

/*
 * LevelDB
 */

LDB_EXTERN leveldb_t *
leveldb_open(const leveldb_options_t *options,
             const char *name, char **errptr);

LDB_EXTERN void
leveldb_close(leveldb_t *db);

LDB_EXTERN void
leveldb_put(leveldb_t *db, const leveldb_writeoptions_t *options,
                           const char *key, size_t keylen,
                           const char *val, size_t vallen,
                           char **errptr);

LDB_EXTERN void
leveldb_delete(leveldb_t *db, const leveldb_writeoptions_t *options,
                              const char *key, size_t keylen,
                              char **errptr);

LDB_EXTERN void
leveldb_write(leveldb_t *db, const leveldb_writeoptions_t *options,
                             leveldb_writebatch_t *batch,
                             char **errptr);

LDB_EXTERN char *
leveldb_get(leveldb_t *db, const leveldb_readoptions_t *options,
                           const char *key, size_t keylen,
                           size_t *vallen, char **errptr);

LDB_EXTERN leveldb_iterator_t *
leveldb_create_iterator(leveldb_t *db, const leveldb_readoptions_t *options);

LDB_EXTERN const leveldb_snapshot_t *
leveldb_create_snapshot(leveldb_t *db);

LDB_EXTERN void
leveldb_release_snapshot(leveldb_t *db, const leveldb_snapshot_t *snapshot);

LDB_EXTERN char *
leveldb_property_value(leveldb_t *db, const char *propname);

LDB_EXTERN void
leveldb_approximate_sizes(leveldb_t *db, int num_ranges,
                          const char *const *range_start_key,
                          const size_t *range_start_key_len,
                          const char *const *range_limit_key,
                          const size_t *range_limit_key_len,
                          ldb_uint64_t *sizes);

LDB_EXTERN void
leveldb_compact_range(leveldb_t *db,
                      const char *start_key, size_t start_key_len,
                      const char *limit_key, size_t limit_key_len);

LDB_EXTERN void
leveldb_destroy_db(const leveldb_options_t *options,
                   const char *name, char **errptr);

LDB_EXTERN void
leveldb_repair_db(const leveldb_options_t *options,
                  const char *name, char **errptr);

LDB_EXTERN void
leveldb_iter_destroy(leveldb_iterator_t *iter);

LDB_EXTERN unsigned char
leveldb_iter_valid(const leveldb_iterator_t *iter);

LDB_EXTERN void
leveldb_iter_seek_to_first(leveldb_iterator_t *iter);

LDB_EXTERN void
leveldb_iter_seek_to_last(leveldb_iterator_t *iter);

LDB_EXTERN void
leveldb_iter_seek(leveldb_iterator_t *iter, const char *k, size_t klen);

LDB_EXTERN void
leveldb_iter_next(leveldb_iterator_t *iter);

LDB_EXTERN void
leveldb_iter_prev(leveldb_iterator_t *iter);

LDB_EXTERN const char *
leveldb_iter_key(const leveldb_iterator_t *iter, size_t *klen);

LDB_EXTERN const char *
leveldb_iter_value(const leveldb_iterator_t *iter, size_t *vlen);

LDB_EXTERN void
leveldb_iter_get_error(const leveldb_iterator_t *iter, char **errptr);

LDB_EXTERN leveldb_writebatch_t *
leveldb_writebatch_create(void);

LDB_EXTERN void
leveldb_writebatch_destroy(leveldb_writebatch_t *b);

LDB_EXTERN void
leveldb_writebatch_clear(leveldb_writebatch_t *b);

LDB_EXTERN void
leveldb_writebatch_put(leveldb_writebatch_t *b,
                       const char *key, size_t klen,
                       const char *val, size_t vlen);

LDB_EXTERN void
leveldb_writebatch_delete(leveldb_writebatch_t *b,
                          const char *key, size_t klen);

LDB_EXTERN void
leveldb_writebatch_iterate(const leveldb_writebatch_t *b, void *state,
                           void (*put)(void *, const char *k, size_t klen,
                                               const char *v, size_t vlen),
                           void (*del)(void *, const char *k, size_t klen));

LDB_EXTERN void
leveldb_writebatch_append(leveldb_writebatch_t *destination,
                          const leveldb_writebatch_t *source);

LDB_EXTERN leveldb_options_t *
leveldb_options_create(void);

LDB_EXTERN void
leveldb_options_destroy(leveldb_options_t *options);

LDB_EXTERN void
leveldb_options_set_comparator(leveldb_options_t *opt,
                               leveldb_comparator_t *cmp);

LDB_EXTERN void
leveldb_options_set_filter_policy(leveldb_options_t *opt,
                                  leveldb_filterpolicy_t *policy);

LDB_EXTERN void
leveldb_options_set_create_if_missing(leveldb_options_t *opt, unsigned char v);

LDB_EXTERN void
leveldb_options_set_error_if_exists(leveldb_options_t *opt, unsigned char v);

LDB_EXTERN void
leveldb_options_set_paranoid_checks(leveldb_options_t *opt, unsigned char v);

LDB_EXTERN void
leveldb_options_set_env(leveldb_options_t *opt, leveldb_env_t *env);

LDB_EXTERN void
leveldb_options_set_info_log(leveldb_options_t *opt, leveldb_logger_t *l);

LDB_EXTERN void
leveldb_options_set_write_buffer_size(leveldb_options_t *opt, size_t s);

LDB_EXTERN void
leveldb_options_set_max_open_files(leveldb_options_t *opt, int n);

LDB_EXTERN void
leveldb_options_set_cache(leveldb_options_t *opt, leveldb_cache_t *c);

LDB_EXTERN void
leveldb_options_set_block_size(leveldb_options_t *opt, size_t s);

LDB_EXTERN void
leveldb_options_set_block_restart_interval(leveldb_options_t *opt, int n);

LDB_EXTERN void
leveldb_options_set_max_file_size(leveldb_options_t *opt, size_t s);

LDB_EXTERN void
leveldb_options_set_compression(leveldb_options_t *opt, int t);

LDB_EXTERN leveldb_comparator_t *
leveldb_comparator_create(void *state,
                          void (*destructor)(void *),
                          int (*compare)(void *, const char *a, size_t alen,
                                                 const char *b, size_t blen),
                          const char *(*name)(void *));

LDB_EXTERN void
leveldb_comparator_destroy(leveldb_comparator_t *cmp);

LDB_EXTERN leveldb_filterpolicy_t *
leveldb_filterpolicy_create(void *state,
                            void (*destructor)(void *),
                            char *(*create_filter)(void *,
                                                   const char *const *key_array,
                                                   const size_t *key_lengths,
                                                   int num_keys,
                                                   size_t *filter_length),
                            unsigned char (*key_match)(void *,
                                                       const char *key,
                                                       size_t length,
                                                       const char *filter,
                                                       size_t filter_length),
                            const char *(*name)(void *));

LDB_EXTERN void
leveldb_filterpolicy_destroy(leveldb_filterpolicy_t *filter);

LDB_EXTERN leveldb_filterpolicy_t *
leveldb_filterpolicy_create_bloom(int bits_per_key);

LDB_EXTERN leveldb_readoptions_t *
leveldb_readoptions_create(void);

LDB_EXTERN void
leveldb_readoptions_destroy(leveldb_readoptions_t *opt);

LDB_EXTERN void
leveldb_readoptions_set_verify_checksums(leveldb_readoptions_t *opt,
                                         unsigned char v);

LDB_EXTERN void
leveldb_readoptions_set_fill_cache(leveldb_readoptions_t *opt, unsigned char v);

LDB_EXTERN void
leveldb_readoptions_set_snapshot(leveldb_readoptions_t *opt,
                                 const leveldb_snapshot_t *snap);

LDB_EXTERN leveldb_writeoptions_t *
leveldb_writeoptions_create(void);

LDB_EXTERN void
leveldb_writeoptions_destroy(leveldb_writeoptions_t *opt);

LDB_EXTERN void
leveldb_writeoptions_set_sync(leveldb_writeoptions_t *opt,
                              unsigned char v);

LDB_EXTERN leveldb_cache_t *
leveldb_cache_create_lru(size_t capacity);

LDB_EXTERN void
leveldb_cache_destroy(leveldb_cache_t *cache);

LDB_EXTERN leveldb_env_t *
leveldb_create_default_env(void);

LDB_EXTERN void
leveldb_env_destroy(leveldb_env_t *env);

LDB_EXTERN char *
leveldb_env_get_test_directory(leveldb_env_t *env);

LDB_EXTERN void
leveldb_free(void *ptr);

LDB_EXTERN int
leveldb_major_version(void);

LDB_EXTERN int
leveldb_minor_version(void);

#ifdef __cplusplus
}
#endif

#endif /* LCDB_C_H */
